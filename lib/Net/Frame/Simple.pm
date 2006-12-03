#
# $Id: Simple.pm,v 1.5 2006/12/03 16:24:46 gomor Exp $
#
package Net::Frame::Simple;
use warnings;
use strict;

our $VERSION = '1.00_01';

require Class::Gomor::Array;
our @ISA = qw(Class::Gomor::Array);

our @AS = qw(
   raw
   reply
   timestamp
   firstLayer
   padding
   ref
   _canMatchLayer
   _getKey
   _getKeyReverse
);
our @AA = qw(
   layers
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);
__PACKAGE__->cgBuildAccessorsArray (\@AA);

no strict 'vars';

use Carp;
use Time::HiRes qw(gettimeofday);
use Net::Frame::Layer qw(:consts);

sub _gettimeofday {
   my ($sec, $usec) = gettimeofday();
   sprintf("%d.%06d", $sec, $usec);
}

sub new {
   my $self = shift->SUPER::new(
      timestamp  => _gettimeofday(),
      firstLayer => NP_LAYER_UNKNOWN,
      layers     => [],
      @_,
   );

   $self->[$__raw] ? $self->unpack : $self->pack;
   $self;
}

# If there are multiple layers of the same type, the upper will be kept
sub _setRef {
   my $self = shift;
   my ($l) = @_;
   $self->[$__ref]->{$l->layer} = $l;
}

sub unpack {
   my $self = shift;

   my $encapsulate = $self->[$__firstLayer];

   if ($encapsulate eq NP_LAYER_UNKNOWN) {
      print("Unable to unpack frame from this layer type.\n");
      return undef;
   }

   my @layers;
   my $n         = 0;
   my $raw       = $self->[$__raw];
   my $rawLength = length($raw);
   my $oRaw      = $raw;
   # No more than a thousand nested layers, maybe should be a parameter
   for (1..1000) {
      last unless $raw;

      my $layer  = 'Net::Frame::'.$encapsulate;
      (my $module = $layer) =~ s/::/\//g;
      eval { require "$module.pm" };
      if ($@) {
         print("*** Net::Frame::$encapsulate module not found.\n".
               "*** Either install it (if avail), or implement it.\n".
               "*** You can also send the pcap file to perl\@gomor.org.\n");
         last;
      }
      my $l = $layer->new(raw => $raw)->unpack;

      $encapsulate = $l->encapsulate;
      $raw         = $l->payload;

      push @layers, $l;
      # If there are multiple layers of the same type, the upper will be kept
      $self->_setRef($l);

      last unless $encapsulate;

      if ($encapsulate eq NP_LAYER_UNKNOWN) {
         print("Unable to unpack next layer, not yet implemented in layer: ".
               "$n:@{[$l->layer]}\n");
         last;
      }

      $oRaw = $raw;
   }

   if (@layers > 0) {
      $self->[$__layers] = \@layers;
      $self->_getPadding($rawLength);
      $self->_searchCanGetKeyLayer;
      $self->_searchCanGetKeyReverseLayer;
      $self->_searchCanMatchLayer;
      return $self;
   }

   undef;
}

sub computeLengths {
   my $self = shift;

   my $params;
   for my $l (@{$self->[$__layers]}) {
      do { $params->{ICMPv4_Type} = $l; next } if $l->layer =~ /^ICMPv4./;
   }

   my $icmp4Type = $params->{ICMPv4_Type};

   if (exists $self->[$__ref]->{IPv4}) {
      my $ip4 = $self->[$__ref]->{IPv4};
      if (exists $self->[$__ref]->{TCP}) {
         my $tcp = $self->[$__ref]->{TCP};
         $tcp->computeLengths;
         $ip4->computeLengths({
            payloadLength => $tcp->getLength + $tcp->getPayloadLength,
         });
      }
      elsif (exists $self->[$__ref]->{UDP}) {
         my $udp = $self->[$__ref]->{UDP};
         $udp->computeLengths;
         $ip4->computeLengths({
            payloadLength => $udp->getLength + $udp->getPayloadLength,
         });
      }
      elsif (exists $self->[$__ref]->{ICMPv4} && $icmp4Type) {
         my $icmp4 = $self->[$__ref]->{ICMPv4};
         $ip4->computeLengths({
            payloadLength => $icmp4->getLength + $icmp4Type->getLength,
         });
      }
   }

   1;
}

sub computeChecksums {
   my $self = shift;

   my $params;
   for my $l (@{$self->[$__layers]}) {
      do { $params->{ICMPv4_Type} = $l; next } if $l->layer =~ /^ICMPv4./;
   }

   my $icmp4Type = $params->{ICMPv4_Type};

   if (exists $self->[$__ref]->{IPv4}) {
      my $ip4 = $self->[$__ref]->{IPv4};
      if (exists $self->[$__ref]->{ETH}) {
         $ip4->computeChecksums;
      }

      if (exists $self->[$__ref]->{TCP}) {
         $self->[$__ref]->{TCP}->computeChecksums({
            type => 'IPv4',
            src  => $ip4->src,
            dst  => $ip4->dst,
         });
      }
      elsif (exists $self->[$__ref]->{UDP}) {
         $self->[$__ref]->{UDP}->computeChecksums({
            type => 'IPv4',
            src  => $ip4->src,
            dst  => $ip4->dst,
         });
      }
      elsif (exists $self->[$__ref]->{ICMPv4} && $icmp4Type) {
         $self->[$__ref]->{ICMPv4}->computeChecksums({
            payload => $icmp4Type,
         });
      }
   }

   1;
}

sub pack {
   my $self = shift;

   # If there are multiple layers of the same type,
   # the upper will be kept for the reference
   $self->_setRef($_) for @{$self->[$__layers]};

   $self->computeLengths;
   $self->computeChecksums;

   my $raw = '';
   $raw .= $_->pack for @{$self->[$__layers]};

   $raw .= $self->[$__padding] if $self->[$__padding];

   $self->_searchCanGetKeyLayer;
   $self->_searchCanGetKeyReverseLayer;
   $self->_searchCanMatchLayer;

   $self->[$__raw] = $raw;
}

sub _getPadding {
   my $self = shift;
   my ($rawLength) = @_;

   my $last = ${$self->[$__layers]}[-1];

   # Last layer has no payload, so no padding
   return unless $last->payload;

   my $tLen = 0;
   for my $l (@{$self->[$__layers]}) {
      if ($l->layer eq 'IPv4') {
         $tLen += $l->length;
         last;
      }
      elsif ($l->layer eq 'IPv6') {
         $tLen += $l->getPayloadLength;
         last;
      }
      $tLen += $l->getLength;
   }

   # No padding
   return if $rawLength == $tLen;

   my $pLen    = ($rawLength > $tLen) ? ($rawLength - $tLen) : 0;
   my $padding = substr($self->[$__raw], $tLen, $pLen);
   $self->[$__padding] = $padding;
   $last->payload(undef);
}

sub send {
   my $self = shift;
   my ($oWrite) = @_;
   $oWrite->send($self->[$__raw]);
}

sub reSend { my $self = shift; $self->send unless $self->[$__reply] }

sub _searchCanMatchLayer {
   my $self = shift;
   for my $l (reverse @{$self->[$__layers]}) {
      if ($l->can('match')) {
         $self->[$___canMatchLayer] = $l;
         last;
      }
   }
   undef;
}

sub _searchCanGetKeyLayer {
   my $self = shift;
   for my $l (reverse @{$self->[$__layers]}) {
      if ($l->can('getKey')) {
         $self->[$___getKey] = $l->getKey;
         last;
      }
   }
}

sub _searchCanGetKeyReverseLayer {
   my $self = shift;
   for my $l (reverse @{$self->[$__layers]}) {
      if ($l->can('getKeyReverse')) {
         $self->[$___getKeyReverse] = $l->getKeyReverse;
         last;
      }
   }
}

sub _recv {
   my $self = shift;
   my ($oDump) = @_;

   my $layer = $self->[$___canMatchLayer];

   for my $this ($oDump->getFramesFor($self)) {
      next unless $this->[$__timestamp] ge $self->[$__timestamp];

      if (exists $this->[$__ref]->{$layer->layer}) {
         return $this if $layer->match($this->[$__ref]->{$layer->layer});
      }
   }

   undef;
}

sub recv {
   my $self = shift;
   my ($oDump) = @_;

   # We already have the reply
   $self->[$__reply] and return $self->[$__reply];

   # Is there anything waiting ?
   my $h = $oDump->next or return undef;

   my $oSimple = Net::Frame::Simple->new(
      raw        => $h->{raw},
      firstLayer => $h->{firstLayer},
      timestamp  => $h->{timestamp},
   );
   $oDump->store($oSimple);

   if (my $reply = $self->_recv($oDump)) {
      $self->cgDebugPrint(1, "Reply received");
      return $self->[$__reply] = $reply;
   }

   undef;
}

# Needed by Net::Frame::Dump
sub getKey        { shift->[$___getKey]        || 'all' }
sub getKeyReverse { shift->[$___getKeyReverse] || 'all' }

sub print {
   my $self = shift;

   my $str = '';
   my $last;
   for my $l (@{$self->[$__layers]}) {
      $str .= $l->print."\n";
      $last = $l;
   }
   $str =~ s/\n$//s;

   # Print remaining to be decoded, if any
   if ($last && $last->payload) {
      $str .= "\n".$last->layer.': payload:'.CORE::unpack('H*', $last->payload);
   }

   # Print the padding, if any
   if ($self->[$__padding]) {
      $str .= "\n".'Padding: '.CORE::unpack('H*', $self->[$__padding]);
   }

   $str;
}

sub dump {
   my $self = shift;

   my $str = '';
   for (@{$self->[$__layers]}) {
      $str .= $_->dump."\n";
   }

   if ($self->[$__padding]) {
      $str .= 'Padding: '.CORE::unpack('H*', $self->[$__padding])."\n";
   }

   $str;
}

1;

__END__

=head1 NAME

Net::Frame::Simple - frame crafting made easy

=head1 SYNOPSIS

   require Net::Packet::Frame;

   # Because we passed a layer 3 object, a Net::Packet::DescL3 object 
   # will be created automatically, by default. See Net::Packet::Env 
   # regarding changing this behaviour. Same for Net::Packet::Dump.
   my $frame = Net::Packet::Frame->new(
      l3 => $ipv4,  # Net::Packet::IPv4 object
      l4 => $tcp,   # Net::Packet::TCP object
                    # (here, a SYN request, for example)
   );

   # Without retries
   $frame->send;
   sleep(3);
   if (my $reply = $frame->recv) {
      print $reply->l3->print."\n";
      print $reply->l4->print."\n";
   }

   # Or with retries
   for (1..3) {
      $frame->reSend;

      until ($Env->dump->timeout) {
         if (my $reply = $frame->recv) {
            print $reply->l3->print."\n";
            print $reply->l4->print."\n";
            last;
         }
      }
   }

=head1 DESCRIPTION

In B<Net::Packet>, each sent and/or received frame is parsed and converted into a B<Net::Packet::Frame> object. Basically, it encapsulates various layers (2, 3, 4 and 7) into an object, making it easy to get or set information about it.

When you create a frame object, a B<Net::Packet::Desc> object is created if none is found in the default B<$Env> object (from B<Net::Packet> module), and a B<Net::Packet::Dump> object is also created if none is found in this same B<$Env> object. You can change this beheaviour, see B<Net::Packet::Env>.

Two B<new> invocation method exist, one with attributes passing, another with B<raw> attribute. This second method is usually used internally, in order to unpack received frame into all corresponding layers.

=head1 ATTRIBUTES

=over 4

=item B<env>

Stores the B<Net::Packet::Env> object. The default is to use B<$Env> from B<Net::Packet>. So, you can send/recv frames to/from different environements.

=item B<raw>

Pass this attribute when you want to decode a raw string captured from network. Usually used internally.

=item B<padding>

In Ethernet world, a frame should be at least 60 bytes in length. So when you send frames at layer 2, a padding is added in order to achieve this length, avoiding a local memory leak to network. Also, when you receive a frame from network, this attribute is filled with what have been used to pad it. This padding feature currently works for IPv4 and ARP frames.

=item B<l2>

Stores a layer 2 object. See B<Net::Packet> for layer 2 classes hierarchy.

=item B<l3>

Stores a layer 3 object. See B<Net::Packet> for layer 3 classes hierarchy.

=item B<l4>

Stores a layer 4 object. See B<Net::Packet> for layer 4 classes hierarchy.

=item B<l7>

Stores a layer 7 object. See B<Net::Packet::Layer7>.

=item B<reply>

When B<recv> method has been called on a frame object, and a corresponding reply has been catched, a pointer is stored in this attribute.

=item B<timestamp>

When a frame is packed/unpacked, the happening time is stored here.

=item B<encapsulate>

Give the type of the first encapsulated layer. It is a requirement to parse a user provided raw string.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. If a B<$Env->desc> object does not exists, one is created by analyzing attributes (so, either one of B<Net::Packet::DescL2>, B<Net::Packet::DescL3>. B<Net::Packet::DescL4> cannot be created automatically for now). The same behaviour is true for B<$Env->dump> object. You can change this default creation behaviour, see B<Net::Packet::Env>. Default values:

timestamp: gettimeofday(),

env:       $Env

=item B<getLengthFromL7>

=item B<getLengthFromL4>

=item B<getLengthFromL3>

=item B<getLengthFromL2>

Returns the raw length in bytes from specified layer.

=item B<getLength>

Alias for B<getLengthFromL3>.

=item B<unpack>

Unpacks the raw string from network into various layers. Returns 1 on success, undef on failure.

=item B<pack>

Packs various layers into the raw string to send to network. Returns 1 on success, undef on failure.

=item B<send>

On the first send invocation in your program, the previously created B<Net::Packet::Dump> object is started (if available). That is, packet capturing is run. The B<timestamp> attribute is set to the sending time. The B<env> attribute is used to know where to send this frame.

=item B<reSend>

Will call B<send> method if no frame has been B<recv>'d, that is the B<reply> attribute is undef.

=item B<getFilter>

Will return a string which is a pcap filter, and corresponding to what you should receive compared with the frame request.

=item B<recv>

Searches B<framesSorted> or B<frames> from B<Net::Packet::Dump> for a matching response. If a reply has already been received (that is B<reply> attribute is already set), undef is returned. It no reply is received, return undef, else the B<Net::Packet::Frame> response.

=item B<print>

Just returns a string in a human readable format describing attributes found in the layer.

=item B<dump>

Just returns a string in hexadecimal format which is how the layer appears on the network.

=item B<isEth>

=item B<isRaw>

=item B<isNull>

=item B<isSll>

=item B<isPpp>

=item B<isArp>

=item B<isIpv4>

=item B<isIpv6>

=item B<isIp> - either IPv4 or IPv6

=item B<isPpplcp>

=item B<isVlan>

=item B<isPppoe>

=item B<isLlc>

=item B<isTcp>

=item B<isUdp>

=item B<isIcmpv4>

=item B<isIcmp> - currently only ICMPv4

=item B<isCdp>

=item B<isStp>

=item B<isOspf>

=item B<isIgmpv4>

=item B<is7>

Returns 1 if the B<Net::Packet::Frame> is of specified layer, 0 otherwise.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
