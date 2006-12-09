#!/usr/bin/perl
use strict;
use warnings;

my $src    = '192.168.0.10';
my $target = '192.168.0.1';
my $port   = 22;

use Net::Frame::Simple;
use Net::Frame::IPv4;
use Net::Frame::TCP;

my $ip4 = Net::Frame::IPv4->new(
   src => $src,
   dst => $target,
);
my $tcp = Net::Frame::TCP->new(
   dst     => $port,
   options => "\x02\x04\x54\x0b",
   payload => 'test',
);

my $oSimple = Net::Frame::Simple->new(
   layers => [ $ip4, $tcp ],
);

print $oSimple->print."\n";
print $oSimple->dump."\n";
