#
# $Id: Makefile.PL,v 1.2 2006/12/03 16:27:53 gomor Exp $
#
use ExtUtils::MakeMaker;

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
