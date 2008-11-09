#
# $Id: Simple.pm 303 2008-11-09 22:00:02Z gomor $
#
package Net::Frame::Simple;
use warnings; use strict;

our $VERSION = '1.03';

use Class::Gomor::Array;
use Exporter;
our @ISA = qw(Class::Gomor::Array Exporter);
our @EXPORT_OK = qw(
   $NoComputeLengths
   $NoComputeChecksums
);
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

our $NoComputeLengths   = 0;
our $NoComputeChecksums = 0;

sub new {
   my $self = shift->SUPER::new(
      timestamp  => _gettimeofday(),
      firstLayer => NF_LAYER_UNKNOWN,
      layers     => [],
      @_,
   );

   $self->[$__raw] ? $self->unpack : $self->pack;
   $self;
}

sub newFromDump {
   my $self = shift;
   my ($h) = @_;
   $self->new(
      timestamp  => $h->{timestamp},
      firstLayer => $h->{firstLayer},
      raw        => $h->{raw},
   );
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

   if ($encapsulate eq NF_LAYER_UNKNOWN) {
      print("Unable to unpack frame from this layer type.\n");
      return undef;
   }

   my @layers;
   my $n         = 0;
   my $raw       = $self->[$__raw];
   my $rawLength = length($raw);
   my $oRaw      = $raw;
   my $prevLayer;
   # No more than a thousand nested layers, maybe should be a parameter
   for (1..1000) {
      last unless $raw;

      my $layer = 'Net::Frame::Layer::'.$encapsulate;
      eval "require $layer";
      if ($@) {
         print("*** $layer module not found.\n".
               "*** Either install it (if avail), or implement it.\n".
               "*** You can also send the pcap file to perl\@gomor.org.\n");
               # XXX: use debug feature from Class::Gomor
               #"*** You can also send the pcap file to perl\@gomor.org.\n".
               #"*** ERROR: $@\n");

         if ($prevLayer) {
            $prevLayer->nextLayer(NF_LAYER_NOT_AVAILABLE);
         }

         last;
      }
      my $l = $layer->new(raw => $raw)->unpack
         or last;

      $encapsulate = $l->encapsulate;
      $raw         = $l->payload;

      push @layers, $l;
      # If there are multiple layers of the same type, the upper will be kept
      $self->_setRef($l);

      last unless $encapsulate;

      if ($encapsulate eq NF_LAYER_UNKNOWN) {
         print("Unable to unpack next layer, not yet implemented in layer: ".
               "$n:@{[$l->layer]}\n");
         last;
      }

      $prevLayer = $l;
      $oRaw      = $raw;
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

   if (exists $self->[$__ref]->{IPv4} || exists $self->[$__ref]->{IPv6}) {
      my $ip = $self->[$__ref]->{IPv4} || $self->[$__ref]->{IPv6};
      if (exists $self->[$__ref]->{TCP}) {
         my $tcp = $self->[$__ref]->{TCP};
         $tcp->computeLengths;
         $ip->computeLengths({
            payloadLength => $tcp->getLength + $tcp->getPayloadLength,
         });
      }
      elsif (exists $self->[$__ref]->{UDP}) {
         my $udp = $self->[$__ref]->{UDP};
         $udp->computeLengths;
         $ip->computeLengths({
            payloadLength => $udp->getLength + $udp->getPayloadLength,
         });
      }
      elsif (exists $self->[$__ref]->{ICMPv4}
         ||  exists $self->[$__ref]->{ICMPv6}) {
         my $icmp = $self->[$__ref]->{ICMPv4} || $self->[$__ref]->{ICMPv6};
         $ip->computeLengths({ payloadLength => $icmp->getLength });
      }
   }
   else {
      my $layers = $self->[$__layers];
      for my $l (reverse @$layers) {
         $l->computeLengths($layers);
      }
   }

   return 1;
}

sub computeChecksums {
   my $self = shift;

   if (exists $self->[$__ref]->{IPv4} || exists $self->[$__ref]->{IPv6}) {
      my $ip = $self->[$__ref]->{IPv4} || $self->[$__ref]->{IPv6};
      if (exists $self->[$__ref]->{ETH}) {
         $ip->computeChecksums;
      }

      if (exists $self->[$__ref]->{TCP}) {
         $self->[$__ref]->{TCP}->computeChecksums({
            type => $ip->layer,
            src  => $ip->src,
            dst  => $ip->dst,
         });
      }
      elsif (exists $self->[$__ref]->{UDP}) {
         $self->[$__ref]->{UDP}->computeChecksums({
            type => $ip->layer,
            src  => $ip->src,
            dst  => $ip->dst,
         });
      }
      elsif (exists $self->[$__ref]->{ICMPv4}) {
         $self->[$__ref]->{ICMPv4}->computeChecksums;
      }
      elsif (exists $self->[$__ref]->{ICMPv6}) {
         $self->[$__ref]->{ICMPv6}->computeChecksums({
            src           => $ip->src,
            dst           => $ip->dst,
            nextHeader    => $ip->nextHeader,
            payloadLength => $ip->payloadLength,
         });
      }
   }
   else {
      my $layers = $self->[$__layers];
      for my $l (reverse @$layers) {
         $l->computeChecksums($layers);
      }
   }

   return 1;
}

sub pack {
   my $self = shift;

   # If there are multiple layers of the same type,
   # the upper will be kept for the reference
   $self->_setRef($_) for @{$self->[$__layers]};

   $self->computeLengths   unless $NoComputeLengths;
   $self->computeChecksums unless $NoComputeChecksums;

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

   # If last layer has unknown layer payload, we do not 
   # try to get padding
   if ($last->nextLayer eq NF_LAYER_NOT_AVAILABLE) {
      return;
   }

   my $tLen = 0;
   for my $l (@{$self->[$__layers]}) {
      if ($l->layer eq 'IPv4') {
         $tLen += $l->length;
         last;
      }
      elsif ($l->layer eq 'IPv6') {
         $tLen += $l->getLength;
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

   # Now, split padding between true padding and true payload
   my $payloadLength = length($last->payload);
   if ($payloadLength > $pLen) {
      my $payload = substr($last->payload, 0, ($payloadLength - $pLen));
      $last->payload($payload);
   }
   else {
      $last->payload(undef);
   }
}

sub send {
   my $self = shift;
   my ($oWrite) = @_;
   $oWrite->send($self->[$__raw]);
}

sub reSend { my $self = shift; $self->send(shift()) unless $self->[$__reply] }

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
      next unless $this->[$__timestamp] gt $self->[$__timestamp];

      # We must put ICMPv4 before, because the other will 
      # always match for UDP.
      if (exists $this->[$__ref]->{ICMPv4}
      &&  (exists $this->[$__ref]->{UDP} || exists $this->[$__ref]->{TCP})) {
         if (exists $this->[$__ref]->{$layer->layer}) {
            return $this
               if $this->[$__ref]->{$layer->layer}->getKey eq $layer->getKey;
         }
      }
      elsif (exists $this->[$__ref]->{$layer->layer}) {
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

   my $oSimple = Net::Frame::Simple->newFromDump($h);
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

   my $raw = '';
   $raw .= $_->raw for @{$self->[$__layers]};
   $raw .= $self->[$__padding] if $self->[$__padding];

   CORE::unpack('H*', $raw);
}

1;

__END__

=head1 NAME

Net::Frame::Simple - frame crafting made easy

=head1 SYNOPSIS

   # We build a TCP SYN
   my $src    = '192.168.0.10';
   my $target = '192.168.0.1';
   my $port   = 22;

   use Net::Frame::Simple;
   use Net::Frame::Layer::IPv4;
   use Net::Frame::Layer::TCP;

   my $ip4 = Net::Frame::Layer::IPv4->new(
      src => $src,
      dst => $target,
   );
   my $tcp = Net::Frame::Layer::TCP->new(
      dst     => $port,
      options => "\x02\x04\x54\x0b",
      payload => 'test',
   );

   my $oSimple = Net::Frame::Simple->new(
      layers => [ $ip4, $tcp ],
   );

   # Now, the frame is ready to be send to the network
   # We open a sender object, and a retriever object
   use Net::Write::Layer3;
   use Net::Frame::Dump::Online;

   my $oWrite = Net::Write::Layer3->new(dst => $target);
   my $oDump  = Net::Frame::Dump::Online->new(dev => $oDevice->dev);
   $oDump->start;
   $oWrite->open;

   # We send the frame
   $oSimple->send($oWrite);

   # And finally, waiting for the response
   until ($oDump->timeout) {
      if (my $recv = $oSimple->recv($oDump)) {
         print "RECV:\n".$recv->print."\n";
         last;
      }
   }

   $oWrite->close;
   $oDump->stop;

=head1 DESCRIPTION

This module is part of B<Net::Frame> frame crafting framework. It is totally optional, but can make playing with the network far easier.

Basically, it hides the complexity of frame forging, sending, and receiving, by providing helper methods, which will analyze internally how to assemble frames and find responses to probes.

For example, it will take care of computing lengths and checksums, and matching a response frame to the requesting frame.

=head1 ATTRIBUTES

=over 4

=item B<raw>

Where the packed frame will be stored, or used to unpack a raw string taken from the network (or elsewhere).

=item B<timestamp>

The frame timestamp.

=item B<firstLayer>

We cannot know by which layer a frame begins, so this tells how to start unpacking a raw data.

=item B<padding>

Sometimes, frames are padded to achieve 60 bytes in length. The padding will be stored here, or if you craft a frame, you can manually add your own padding.

=item B<reply>

When the B<recv> method is called, and a corresponding reply has been found, it is stored here.

=item B<layers>

This one is an arrayref. It will store all layers to use within the B<Net::Frame::Simple> object.

=item B<ref>

This is a hashref that stores all layers. The key is the layer type (example: TCP: $oSimple->ref->{TCP}). If the frame contains multiple layers of the same type, only the one found at upper level will be kept (in fact, the latest analyzed one, aka LIFO).


=back

=head1 METHODS

=over 4

=item B<new> (hash)

Object constructor. You can pass attributes in a hash as a parameter. Also note that when you call it with B<layers> attribute set, it will automatically call B<computeLengths>, B<computeChecksums> and B<pack> for you. And when you pass B<raw> attribute, it will call B<unpack> for you too, building layers and storing them in B<layers> attribute.

=item B<newFromDump> (hashref)

When B<Net::Frame::Dump> B<next> method is called, and there is a frame waiting, it returns a hashref with specific values. You can directly use it as a parameter for this method, which will create a new B<Net::Frame::Simple> object.

=item B<computeLengths>

This one hides the manual hassle of calling B<computeLengths> method for each layers. It takes no parameter, it will know internally what to do.

=item B<computeChecksums>

Same as above, but for checksums. you MUST call the previous one before this one.

=item B<pack>

Will pack all layers to to B<raw> attribute, ready to be sent to the network.

=item B<unpack>

Will unpack a raw string from the B<raw> attribute into respective layers.

=item B<getKey>

=item B<getKeyReverse>

These two methods are basically used to increase the speed when using B<recv> method.

=item B<recv> (Net::Frame::Dump object)

When you want to search for the response of your probe, you call it by specifying from which B<Net::Frame::Dump> object to search. It then returns a B<Net::Frame::Simple> object if a match is found, or undef if not.

=item B<send> (Net::Write object)

Will send to the B<Net::Write> object the raw string describing the B<Net::Frame::Simple> object.

=item B<reSend> (Net::Write object)

You can also B<reSend> the frame, it will only rewrite it to the network if no B<reply> has already been found.

=item B<print>

Prints all layers in human readable format.

=item B<dump>

Dumps the B<raw> string in hexadecimal format.

=back

=head1 SEE ALSO

L<Net::Write>, L<Net::Frame::Dump>

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006-2008, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
