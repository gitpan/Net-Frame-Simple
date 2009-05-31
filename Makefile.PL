#
# $Id: Makefile.PL 308 2009-05-31 13:30:08Z gomor $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::Frame::Simple',
   VERSION_FROM  => 'lib/Net/Frame/Simple.pm',
   LICENSE       => 'artistic',
   ABSTRACT_FROM => 'lib/Net/Frame/Simple.pm',
   AUTHOR        => 'GomoR <gomor-cpan_at_gomor.org>',
   PREREQ_PM     => {
      Class::Gomor => '1.00',
      Net::Frame   => 0,
   },
);
