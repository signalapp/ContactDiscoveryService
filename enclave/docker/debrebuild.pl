#!/usr/bin/perl
#
# Copyright 2016 Johannes Schauer
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

use strict;
use warnings;

use Dpkg::Control;
use Dpkg::Index;
use Dpkg::Deps;
use Dpkg::Source::Package;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use JSON::PP;
use Time::Piece;
use File::Basename;

eval {
    require LWP::Simple;
    require LWP::UserAgent;
    no warnings;
    $LWP::Simple::ua = LWP::UserAgent->new(agent => 'LWP::UserAgent/srebuild');
    $LWP::Simple::ua->env_proxy();
};
if ($@) {
    if ($@ =~ m/Can\'t locate LWP/) {
	die "Unable to run: the libwww-perl package is not installed";
    } else {
	die "Unable to run: Couldn't load LWP::Simple: $@";
    }
}

my $buildinfo = shift @ARGV;
if (not defined($buildinfo)) {
    die "need buildinfo filename";
}

my $outdir = shift @ARGV or die("need output directory path");

# buildinfo support in libdpkg-perl (>= 1.18.11)
my $cdata = Dpkg::Control->new(type => CTRL_FILE_BUILDINFO);

if (not $cdata->load($buildinfo)) {
    die "cannot load $buildinfo";
}

my @architectures = split /\s+/, $cdata->{"Architecture"};
my $build_source = (scalar (grep /^source$/, @architectures)) == 1;
my $build_archall = (scalar (grep /^all$/, @architectures)) == 1;
@architectures = grep {!/^source$/ && !/^all$/} @architectures;
if (scalar @architectures > 1) {
    die "more than one architecture in Architecture field";
}
my $build_archany = (scalar @architectures) == 1;
my $host_arch = undef;
if ($build_archany) {
    $host_arch = $architectures[0];
}

my $build_arch = $cdata->{"Build-Architecture"};
if (not defined($build_arch)) {
    die "need Build-Architecture field";
}
my $inst_build_deps = $cdata->{"Installed-Build-Depends"};
if (not defined($inst_build_deps)) {
    die "need Installed-Build-Depends field";
}

my $srcpkg = Dpkg::Source::Package->new();
$srcpkg->{fields}{'Source'} = $cdata->{"Source"};
$srcpkg->{fields}{'Version'} = $cdata->{"Version"};
my $dsc_fname = (dirname($buildinfo)) .'/'. $srcpkg->get_basename(1) . ".dsc";

my $environment = $cdata->{"Environment"};
if (not defined($environment)) {
    die "need Environment field";
}
$environment =~ s/\n/ /g; # remove newlines
$environment =~ s/^ //; # remove leading whitespace

my $checksums = Dpkg::Checksums->new();
$checksums->add_from_control($cdata);
my @files = $checksums->get_files();

# gather all installed build-depends and figure out the version of base-files
# and dpkg
my $base_files_version;
my $dpkg_version;
my @inst_build_deps = ();
$inst_build_deps = deps_parse($inst_build_deps, reduce_arch => 0, build_dep => 0);
if (! defined $inst_build_deps) {
    die "deps_parse failed\n";
}

foreach my $pkg ($inst_build_deps->get_deps()) {
    if (! $pkg->isa('Dpkg::Deps::Simple')) {
	die "dependency disjunctions are not allowed\n";
    }
    if (not defined($pkg->{package})) {
	die "name undefined";
    }
    if (defined($pkg->{relation})) {
	if ($pkg->{relation} ne "=") {
	    die "wrong relation";
	}
	if (not defined($pkg->{version})) {
	    die "version undefined"
	}
    } else {
	die "no version";
    }
    if ($pkg->{package} eq "dpkg") {
	if (defined($dpkg_version)) {
	    die "more than one dpkg\n";
	}
	$dpkg_version = $pkg->{version};
    }
    if ($pkg->{package} eq "base-files") {
	if (defined($base_files_version)) {
	    die "more than one base-files\n";
	}
	$base_files_version = $pkg->{version};
    }
    push @inst_build_deps, { name => $pkg->{package},
	architecture => $pkg->{archqual},
	version => $pkg->{version}
    };
}

open(my $build_deps_fd, '>', "$outdir/build-deps") or die;
foreach my $pkg (@inst_build_deps) {
    my $pkg_name = $pkg->{name};
    my $pkg_ver = $pkg->{version};
    my $pkg_arch = $pkg->{architecture};
    if (($pkg_arch // "") eq "" || $pkg_arch eq "all" || $pkg_arch eq $build_arch) {
	print $build_deps_fd "$pkg_name=$pkg_ver\n";
    } else {
	print $build_deps_fd "$pkg_name:$pkg_arch=$pkg_ver\n";
    }
}

if (!defined($base_files_version)) {
    die "no base-files\n";
}
if (!defined($dpkg_version)) {
    die "no dpkg\n";
}

# figure out the debian release from the version of base-files and dpkg
my $base_dist;

my %base_files_map = (
    "6" => "squeeze",
    "7" => "wheezy",
    "8" => "jessie",
    "9" => "stretch",
    "10" => "buster",
    "11" => "bullseye",
);
my %dpkg_map = (
    "15" => "squeeze",
    "16" => "wheezy",
    "17" => "jessie",
    "18" => "stretch",
    "19" => "buster",
    "20" => "bullseye",
);

$base_files_version =~ s/^(\d+).*/$1/;
$dpkg_version =~ s/1\.(\d+)\..*/$1/;

$base_dist = $base_files_map{$base_files_version};

if (! defined $base_dist) {
    die "base-files version didn't map to any Debian release"
}

if ($base_dist ne $dpkg_map{$dpkg_version}) {
    die "base-files and dpkg versions point to different Debian releases\n";
}

# test if all checksums in the buildinfo file check out

foreach my $fname ($checksums->get_files()) {
    # Re-adding existing files to the checksum object is the current way to
    # ask Dpkg to check the checksums for us
    $checksums->add_from_file((dirname($buildinfo)) .'/'. $fname);
}

# setup a temporary apt directory

my $tempdir = tempdir(CLEANUP => 1);

foreach my $d (('/etc/apt', '/etc/apt/apt.conf.d', '/etc/apt/preferences.d',
	'/etc/apt/trusted.gpg.d', '/etc/apt/sources.list.d',
	'/var/lib/apt/lists/partial',
	'/var/cache/apt/archives/partial', '/var/lib/dpkg')) {
    make_path("$tempdir/$d");
}

open(FH, '>', "$tempdir/etc/apt/sources.list");
print FH <<EOF;
deb http://httpredir.debian.org/debian/ $base_dist main
deb http://security.debian.org/ $base_dist/updates main
EOF
close FH;
# Create dpkg status
open(FH, '>', "$tempdir/var/lib/dpkg/status");
close FH; #empty file
# Create apt.conf
my $aptconf = "$tempdir/etc/apt/apt.conf";
open(FH, ">$aptconf");

# We create an apt.conf and pass it to apt via the APT_CONFIG environment
# variable instead of passing all options via the command line because
# otherwise apt will read the system's config first and might get unwanted
# configuration options from there. See apt.conf(5) for the order in which
# configuration options are read.
#
# While we are at it, we also set all other options through our custom
# apt.conf.
#
# Apt::Architecture has to be set because otherwise apt will default to the
# architecture apt was compiled for.
#
# Apt::Architectures has to be set or otherwise apt will use dpkg to find all
# foreign architectures of the system running apt.
#
# Dir::State::status has to be set even though Dir is set because Dir::State
# is set to var/lib/apt, so Dir::State::status would be below that but really
# isn't and without an absolute path, Dir::State::status would be constructed
# from Dir + Dir::State + Dir::State::status. This has been fixed in apt
# commit 475f75506db48a7fa90711fce4ed129f6a14cc9a.
#
# Acquire::Check-Valid-Until has to be set to false because the snapshot
# timestamps might be too far in the past to still be valid.
#
# Acquire::Languages has to be set to prevent downloading of translations from
# the mirrors.
#
# Binary::apt-get::Acquire::AllowInsecureRepositories has to be set to false
# so that apt-get update fails if repositories cannot be authenticated. The
# default value of this option will change to true with apt from Debian
# Buster.

print FH <<EOF;
Apt {
   Architecture "$build_arch";
   Architectures "$build_arch";
};

Dir "$tempdir";
Dir::State::status "$tempdir/var/lib/dpkg/status";
Acquire::Check-Valid-Until "false";
Acquire::Languages "none";
Binary::apt-get::Acquire::AllowInsecureRepositories "false";
EOF
close FH;

# add the removed keys because they are not returned by Dpkg::Vendor
# we don't need the Ubuntu vendor now but we already put the comments to
# possibly extend this script to other Debian derivatives
my @keyrings = ();
my $debianvendor = Dpkg::Vendor::Debian->new();
push @keyrings, $debianvendor->run_hook('archive-keyrings');
push @keyrings, $debianvendor->run_hook('archive-keyrings-historic');
#my $ubuntuvendor = Dpkg::Vendor::Ubuntu->new();
#push @keyrings, $ubuntuvendor->run_hook('archive-keyrings');
#push @keyrings, $ubuntuvendor->run_hook('archive-keyrings-historic');

foreach my $keyring (@keyrings) {
    my $base = basename $keyring;
    print "$keyring\n";
    if (-f $keyring) {
	print "linking $tempdir/etc/apt/trusted.gpg.d/$base to $keyring\n";
	symlink $keyring, "$tempdir/etc/apt/trusted.gpg.d/$base";
    }
}

$ENV{'APT_CONFIG'} = $aptconf;

0 == system 'apt-get', 'update' or die "apt-get update failed\n";

my $key_func = sub {
    return $_[0]->{Package} . ' ' . $_[0]->{Version} . ' ' . $_[0]->{Architecture};
};
my $index = Dpkg::Index->new(get_key_func=>$key_func);

open(my $fd, '-|', 'apt-get', 'indextargets', '--format', '$(FILENAME)', 'Created-By: Packages');
while (my $fname = <$fd>) {
    chomp $fname;
    print "parsing $fname...\n";
    open(my $fd2, '-|', '/usr/lib/apt/apt-helper', 'cat-file', $fname);
    $index->parse($fd2, "pipe") or die "cannot parse Packages file\n";
    close($fd2);
}
close($fd);

# go through all packages in the Installed-Build-Depends field and find out
# the timestamps at which they were first seen each
my %notfound_timestamps;

foreach my $pkg (@inst_build_deps) {
    my $pkg_name = $pkg->{name};
    my $pkg_ver = $pkg->{version};
    my $pkg_arch = $pkg->{architecture};

    # check if we really need to acquire this package from snapshot.d.o or if
    # it already exists in the cache
    if (defined $pkg->{architecture}) {
	if ($index->get_by_key("$pkg_name $pkg_ver $pkg_arch")) {
	    print "skipping $pkg_name $pkg_ver\n";
	    next;
	}
    } else {
	if ($index->get_by_key("$pkg_name $pkg_ver $build_arch")) {
	    $pkg->{architecture} = $build_arch;
	    print "skipping $pkg_name $pkg_ver\n";
	    next;
	}
	if ($index->get_by_key("$pkg_name $pkg_ver all")) {
	    $pkg->{architecture} = "all";
	    print "skipping $pkg_name $pkg_ver\n";
	    next;
	}
    }

    print "retrieving snapshot.d.o data for $pkg_name $pkg_ver\n";
    my $json_url = "http://snapshot.debian.org/mr/binary/$pkg_name/$pkg_ver/binfiles?fileinfo=1";
    my $content = LWP::Simple::get($json_url);
    die "cannot retrieve $json_url" unless defined $content;
    my $json = JSON::PP->new();
    # json options taken from debsnap
    my $json_text = $json->allow_nonref->utf8->relaxed->decode($content);
    die "cannot decode json" unless defined $json_text;
    my $pkg_hash;
    if (scalar @{$json_text->{result}} == 1) {
	# if there is only a single result, then the package must either be
	# Architecture:all, be the build architecture or match the requested
	# architecture
	$pkg_hash = ${$json_text->{result}}[0]->{hash};
	$pkg->{architecture} = ${$json_text->{result}}[0]->{architecture};
	# if a specific architecture was requested, it should match
	if (defined $pkg_arch && $pkg_arch ne $pkg->{architecture}) {
	    die "package $pkg_name was explicitly requested for $pkg_arch but only $pkg->{architecture} was found\n";
	}
	# if no specific architecture was requested, it should be the build
	# architecture
	if (! defined $pkg_arch && $build_arch ne $pkg->{architecture} && "all" ne $pkg->{architecture}) {
	    die "package $pkg_name was implicitly requested for $pkg_arch but only $pkg->{architecture} was found\n";
	}
    } else {
	# Since the package occurs more than once, we expect it to be of
	# Architecture:any
	#
	# If no specific architecture was requested, look for the build
	# architecture
	if (! defined $pkg_arch) {
	    $pkg_arch = $build_arch;
	}
	foreach my $result (@{$json_text->{result}}) {
	    if ($result->{architecture} eq $pkg_arch) {
		$pkg_hash = $result->{hash};
		last;
	    }
	}
	if (! defined($pkg_hash)) {
	    die "cannot find package in architecture $pkg_arch\n";
	}
	# we now know that this package is not architecture:all but has a
	# concrete architecture
	$pkg->{architecture} = $pkg_arch;
    }
    # assumption: package is from Debian official (and not ports)
    my @package_from_main = grep { $_->{archive_name} eq "debian" } @{$json_text->{fileinfo}->{$pkg_hash}};
    if (scalar @package_from_main > 1) {
        die "more than one package with the same hash in Debian official\n";
    }
    if (scalar @package_from_main == 0) {
        die "no package with the right hash in Debian official\n";
    }
    my $date = $package_from_main[0]->{first_seen};
    $pkg->{first_seen} = $date;
    $notfound_timestamps{$date} = 1;
}

# feed apt with timestamped snapshot.debian.org URLs until apt is able to find
# all the required package versions. We start with the most recent timestamp,
# check which packages cannot be found at that timestamp, add the timestamp of
# the most recent not-found package and continue doing this iteratively until
# all versions can be found.

while (0 < scalar keys %notfound_timestamps) {
    print "left to check: " . (scalar keys %notfound_timestamps) . "\n";
    my @timestamps = map { Time::Piece->strptime($_, '%Y%m%dT%H%M%SZ') } (sort keys %notfound_timestamps);
    my $newest = $timestamps[$#timestamps];
    $newest = $newest->strftime("%Y%m%dT%H%M%SZ");
    delete $notfound_timestamps{$newest};

    my $snapshot_url = "http://snapshot.debian.org/archive/debian/$newest/";

    open(FH, '>>', "$tempdir/etc/apt/sources.list");
    print FH "deb $snapshot_url unstable main\n";
    close FH;

    0 == system 'apt-get', 'update' or die "apt-get update failed";

    my $index = Dpkg::Index->new(get_key_func=>$key_func);
    open(my $fd, '-|', 'apt-get', 'indextargets', '--format', '$(FILENAME)', 'Created-By: Packages');
    while (my $fname = <$fd>) {
	chomp $fname;
	print "parsing $fname...\n";
	open(my $fd2, '-|', '/usr/lib/apt/apt-helper', 'cat-file', $fname);
	$index->parse($fd2, "pipe") or die "cannot parse Packages file\n";
	close($fd2);
    }
    close($fd);
    foreach my $pkg (@inst_build_deps) {
	my $pkg_name = $pkg->{name};
	my $pkg_ver = $pkg->{version};
	my $pkg_arch = $pkg->{architecture};
	my $first_seen = $pkg->{first_seen};
	my $cdata = $index->get_by_key("$pkg_name $pkg_ver $pkg_arch");
	if (not defined($cdata->{"Package"})) {
	    die "cannot find $pkg_name/$pkg_ver/$pkg_arch in dumpavail\n";
	}
	if (defined $first_seen) {
	    delete $notfound_timestamps{$first_seen};
	}
    }
}

0 == system 'cp', "$tempdir/etc/apt/sources.list", "$outdir/sources.list"
    or die "cannot cp $tempdir/etc/apt/sources.list to $outdir/sources.list";
