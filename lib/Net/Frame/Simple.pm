#
# $Id: Simple.pm,v 1.7 2006/12/05 20:37:52 gomor Exp $
#
package Net::Frame::Simple;
use warnings;
use strict;

our $VERSION = '1.00_02';

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
            icmpType => $icmp4Type,
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

=head1 DESCRIPTION

=head1 ATTRIBUTES

=over 4

=back

=head1 METHODS

=over 4

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
