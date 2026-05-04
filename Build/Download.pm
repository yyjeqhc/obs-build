################################################################
#
# Copyright (c) 2021 SUSE LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program (see the file COPYING); if not, write to the
# Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
#
################################################################

package Build::Download;

use strict;

use LWP::UserAgent;
use Digest::MD5 ();
use Digest::SHA ();

our $debug;

# Reuse credentials from osc's config for private OBS instances.  Keeping
# this in Build::Download lets the existing download/cache code paths keep
# working while authenticated OBS URLs gain the Authorization header they need.
our $osc_credentials_loaded;
our @osc_credentials;

sub load_osc_credentials {
  return if $osc_credentials_loaded;
  $osc_credentials_loaded = 1;

  my @files;
  push @files, $ENV{'OSC_CONFIG'} if $ENV{'OSC_CONFIG'};
  push @files, "$ENV{'HOME'}/.config/osc/oscrc" if $ENV{'HOME'};
  push @files, "$ENV{'HOME'}/.oscrc" if $ENV{'HOME'};

  my %seen;
  for my $file (@files) {
    next unless $file && !$seen{$file}++ && -r $file;
    my ($section, %data);
    my $save = sub {
      return unless $section && $section =~ /^https?:\/\//;
      return unless defined($data{'user'}) && defined($data{'pass'});
      push @osc_credentials, { url => $section, user => $data{'user'}, pass => $data{'pass'} };
    };
    my $fd;
    next unless open($fd, '<', $file);
    while (<$fd>) {
      chomp;
      s/\r$//;
      s/^\s+//;
      s/\s+$//;
      next if $_ eq '' || /^#/ || /^;/;
      if (/^\[(.*)\]$/) {
	$save->();
	$section = $1;
	%data = ();
	next;
      }
      next unless /^([^=]+?)\s*=\s*(.*)$/;
      my ($key, $value) = ($1, $2);
      $key =~ s/\s+$//;
      $value =~ s/^['"]//;
      $value =~ s/['"]$//;
      $data{$key} = $value if $key eq 'user' || $key eq 'pass';
    }
    $save->();
    close($fd);
  }
}

sub add_osc_auth_headers {
  my ($url, @hdrs) = @_;

  # Do not overwrite a caller supplied Authorization header.  Some users may
  # intentionally pass a token or another auth scheme for non-osc downloads.
  for (my $i = 0; $i < @hdrs - 1; $i += 2) {
    return @hdrs if lc($hdrs[$i]) eq 'authorization';
  }

  load_osc_credentials();
  my $match;
  my $matchlen = -1;
  my $request_url = $url;

  # Match the longest oscrc URL prefix so a more specific API section wins
  # over a generic one when both are present.
  $request_url =~ s/\/+$//;
  for my $cred (@osc_credentials) {
    my $base = $cred->{'url'};
    $base =~ s/\/+$//;
    next unless $request_url eq $base || index($request_url, "$base/") == 0;
    next if length($base) <= $matchlen;
    $match = $cred;
    $matchlen = length($base);
  }
  return @hdrs unless $match;

  require MIME::Base64;
  my $auth = MIME::Base64::encode_base64("$match->{'user'}:$match->{'pass'}", "");
  return ('Authorization' => "Basic $auth", @hdrs);
}

#
# Create a user agent used to access remote servers
#
sub create_ua {
  my (%opt) = @_;
  my $agent = $opt{'agent'} || 'openSUSE build script';
  my $timeout = $opt{'timeout'} || 60;
  my $ssl_opts = $opt{'ssl_opts'} || { verify_hostname => 1 };
  my $ua = LWP::UserAgent->new(agent => $agent, timeout => $timeout, ssl_opts => $ssl_opts, keep_alive => 3);
  $ua->env_proxy;
  $ua->cookie_jar($opt{'cookie_jar'}) if $opt{'cookie_jar'};
  return $ua;
}

#
# Create a hash context from a digest
#
sub digest2ctx {
  my ($digest) = @_;
  return Digest::SHA->new(1) if $digest =~ /^sha1?:/i;
  return Digest::SHA->new($1) if $digest =~ /^sha(\d+):/i;
  return Digest::MD5->new() if $digest =~ /^md5:/i;
  return undef;
}

#
# Verify that some data matches a digest
#
sub checkdigest {
  my ($data, $digest) = @_;
  my $ctx = digest2ctx($digest);
  die("unsupported digest algo '$digest'\n") unless $ctx;
  $ctx->add($data);
  my $hex = $ctx->hexdigest();
  if (lc($hex) ne lc((split(':', $digest, 2))[1])) {
    die("digest mismatch: $digest, got $hex\n");
  }
}

#
# Call the get method with the correct max size setting
#
sub ua_get {
  my ($ua, $url, $maxsize, @hdrs) = @_;
  my $res;
  print "GET $url\n" if $debug;
  @hdrs = add_osc_auth_headers($url, @hdrs);
  if (defined($maxsize)) {
    my $oldmaxsize = $ua->max_size($maxsize);
    $res = $ua->get($url, @hdrs);
    $ua->max_size($oldmaxsize);
    die("download of $url failed: ".($res->header('X-Died') || "max size exceeded\n")) if $res->header('Client-Aborted');
  } else {
    $res = $ua->get($url, @hdrs);
  }
  return $res;
}

sub ua_head {
  my ($ua, $url, $maxsize, @hdrs) = @_;
  print "HEAD $url\n" if $debug;
  @hdrs = add_osc_auth_headers($url, @hdrs);
  return $ua->head($url, @hdrs);
}

#
# Download a file with the correct max size setting
#
sub ua_mirror {
  my ($ua, $url, $dest, $maxsize, @hdrs) = @_;
  my $res = ua_get($ua, $url, $maxsize, ':content_file', $dest, @hdrs);
  die("download of $url failed: ".$res->header('X-Died')) if $res->header('X-Died');
  if ($res->is_success) {
    my @s = stat($dest);
    die("download of $url did not create $dest: $!\n") unless @s;
    my ($cl) = $res->header('Content-length');
    die("download of $url size mismatch: $cl != $s[7]\n") if defined($cl) && $cl != $s[7];
  }
  return $res;
}

#
# Download data from a server
#
sub fetch {
  my ($url, %opt) = @_;
  my $ua = $opt{'ua'} || create_ua();
  my $retry = $opt{'retry'} || 0;
  my $res;
  my @accept;
  @accept = ('Accept', join(', ', @{$opt{'accept'}})) if $opt{'accept'};
  while (1) {
    $res = ua_get($ua, $url, $opt{'maxsize'}, @accept, @{$opt{'headers'} || []});
    last if $res->is_success;
    return undef if $opt{'missingok'} && $res->code == 404;
    my $status = $res->status_line;
    die("download of $url failed: $status\n") unless $retry-- > 0 && $res->previous;
    warn("retrying $url\n");
  }
  my $data = $res->decoded_content('charset' => 'none');
  my $ct = $res->header('content_type');
  checkdigest($data, $opt{'digest'}) if $opt{'digest'};
  if ($opt{'replyheaders'}) {
    my $data = { $res->flatten() };
    $data = { map {lc($_) => $data->{$_}} sort keys %$data };
    ${$opt{'replyheaders'}} = $data;
  }
  return ($data, $ct);
}

#
# Do a HEAD request
#
sub head {
  my ($url, %opt) = @_;
  my $ua = $opt{'ua'} || create_ua();
  my $retry = $opt{'retry'} || 0;
  my $res;
  my @accept;
  @accept = ('Accept', join(', ', @{$opt{'accept'}})) if $opt{'accept'};
  while (1) {
    $res = ua_head($ua, $url, $opt{'maxsize'}, @accept, @{$opt{'headers'} || []});
    last if $res->is_success;
    return undef if $opt{'missingok'} && $res->code == 404;
    my $status = $res->status_line;
    die("head request of $url failed: $status\n") unless $retry-- > 0 && $res->previous;
    warn("retrying $url\n");
  }
  my $data = { $res->flatten() };
  $data = { map {lc($_) => $data->{$_}} sort keys %$data };
  my $ct = $res->header('content_type');
  return ($data, $ct);
}

#
# Verify that the content of a file matches a digest
#
sub checkfiledigest {
  my ($file, $digest) = @_;
  my $ctx = digest2ctx($digest);
  die("$file: unsupported digest algo '$digest'\n") unless $ctx;
  my $fd;
  open ($fd, '<', $file) || die("$file: $!\n");
  $ctx->addfile($fd);
  close($fd);
  my $hex = $ctx->hexdigest();
  if (lc($hex) ne lc((split(':', $digest, 2))[1])) {
    die("$file: digest mismatch: $digest, got $hex\n");
  }
}

#
# Download a file from a server
#
sub download {
  my ($url, $dest, $destfinal, %opt) = @_;
  my $ua = $opt{'ua'} || create_ua();
  my $retry = $opt{'retry'} || 0;
  while (1) {
    unlink($dest);        # just in case
    my $res = eval { ua_mirror($ua, $url, $dest, $opt{'maxsize'}, @{$opt{'headers'} || []}) };
    if ($@) {
      unlink($dest);
      die($@);
    }
    last if $res->is_success;
    return undef if $opt{'missingok'} && $res->code == 404;
    my $status = $res->status_line;
    die("download of $url failed: $status\n") unless $retry-- > 0 && $res->previous;
    warn("retrying $url\n");
  }
  if ($opt{'digest'}) {
    eval { checkfiledigest($dest, $opt{'digest'}) };
    if ($@ && $opt{'gzip_retry'}) {
      unlink($dest);
      my @newheaders = (@{$opt{'headers'} || []}, 'Accept-Encoding' => 'gzip');
      return download($url, $dest, $destfinal, %opt, 'headers' => \@newheaders, 'gzip_retry' => 0);
    }
    die($@) if $@;
  }
  if ($destfinal) {
    rename($dest, $destfinal) || die("rename $dest $destfinal: $!\n");
  }
  return 1;
}

1;
