use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	      NAME	    => 'Fwctl',
	      AUTHOR	   => 'Francis J. Lacoste <francis.lacoste\@iNsu.Com>',
	      ABSTRACT_FROM => 'Fwctl.pm',
	      VERSION_FROM  => 'Fwctl.pm', # finds $VERSION
	      PREREQ_PM	    => { Net::IPv4Addr => 0.06,
				 IPChains => 0,
			       },
);