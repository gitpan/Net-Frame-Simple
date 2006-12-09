#
# $Id: Makefile.PL,v 1.3 2006/12/09 18:07:11 gomor Exp $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::Frame::Simple',
   VERSION_FROM  => 'lib/Net/Frame/Simple.pm',
   LICENSE       => 'Artistic',
   ABSTRACT_FROM => 'lib/Net/Frame/Simple.pm',
   AUTHOR        => 'GomoR <perl@gomor.org>',
   PREREQ_PM     => {
      Class::Gomor => '1.00',
      Net::Frame   => 0,
   },
);
