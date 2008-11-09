#
# $Id: Makefile.PL 296 2008-11-08 16:48:57Z gomor $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::Frame::Simple',
   VERSION_FROM  => 'lib/Net/Frame/Simple.pm',
   LICENSE       => 'artistic',
   ABSTRACT_FROM => 'lib/Net/Frame/Simple.pm',
   AUTHOR        => 'GomoR <perl@gomor.org>',
   PREREQ_PM     => {
      Class::Gomor => '1.00',
      Net::Frame   => 0,
   },
);
