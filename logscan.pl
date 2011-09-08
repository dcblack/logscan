#!/usr/bin/perl
eval 'exec perl -S $0 ${1+"$@"}'
  if $running_under_some_shell;

require v5.6.1;

exec "perldoc $0" unless @ARGV;

#
# @(#)$Info: logscan - Checks/filters log files for errors.$
#
# @(#)$Copyright: 1997-2001,2008 by David C. Black. All rights reserved. $
# @(#)$Licensing: see LICENSE section of manpage (logscan -h). $
# @(#)$Email: <dcblack@hldwizard.com>. $

use English;
use subs;
use Cwd;
use FileHandle;
STDOUT->autoflush(1);
STDERR->autoflush(1);

use vars qw(
   $auth  $tool  $TOOL  $Tool      $vers  $offl  $revs  $revn
   $when  $user  $date  $toolpath  $wd    $host              
);
   $auth = 'David C Black <dcblack@hldwizard.com>';
   $tool = 'logscan'; $TOOL = uc($tool);
   ($Tool = $tool) =~ s/^./\u$&/;
   $vers = '@(#)$Id: logscan.pl,v 2.50 2008/06/27 16:08:32 dcblack Exp $';
   $offl = '2.47'; # Official revision
   $revs = &RcsVersion($vers); # Revision string
   ($revn = $revs) =~ s/ .*//; # Revision number
   $when = scalar localtime;
   $user = getlogin || (getpwuid($<))[0] || "Intruder!";
   $date = &RcsDate();
   if ($0 =~ m:/([^/]+)$:) {
      ($tooldir,$toolnam) = ($`,$1);
   } else {
      ($tooldir,$toolnam) = ('.',$0);
   }#endif
   $toolpath = $tooldir.'/'.$toolnam;
   $wd = cwd();
   chomp($host = `hostname`);


#############################################################################
# 
# ######   #####  #####   
# #     # #     # #    #  
# #     # #     # #     # 
# ######  #     # #     # 
# #       #     # #     # 
# #       #     # #    #  
# #        #####  #####   
#
#############################################################################
=pod

=head1 NAME

B<logscan> - scan log files for problems & display suspicious areas in context

=head1 SYNOPSIS

B<logscan> -k <KIND> <I<OPTIONS>> <I<FILES-TO-SCAN>>

=head1 SHORT OPTION LIST

 -?          short help (this text)
 -banner     Indicate PASS/FAIL as a banner
 -c <RANGE>  context specificaton (default 3..20)
 -d [<FILE>] dump parsed rules in a compiled format to file (default logscan.rules)
 -e <EXTN>   file name extension used for rules (default '.rules')
 -f <FILE>   include file containing auxiliary rules
 -F <FILE>   include file containing auxiliary rules if present
 -h          display manpage and exit
 -html       produce an html formatted report
 -j          justify rule by displaying rule number in output
 -k <KIND>   base type of rules (Default 'default')
 -keep <N>   maximum number of logfiles to keep (default 1)
 -l <FILE>   log file for results (default $tool.log)
 -man        output manpage to file $tool.1 and exit
 -n          no context, just message pointers
 -o <FILE>   same as -l
 -p <PATH>   search path for rules files (default '/usr/local/etc:.')
 -passfail   indicate PASS/FAIL status as single line message
 -q          quiet (minimal runtime messages)
 -tee        display messages to screen and logfile simultaneously
 -v          verbose (maximal runtime messages)
 -V          display tool version
 -w[COL]     line wrap at COL (default off, 78 if specified w/o COL)
 -x <RULE>   explicit rule (should be quoted)
 -X          exact matching to preclude any allowances
 -INSTALL    simple installation option
 -XL         list built-in extractable files
 -XT <NAME>  Extract build-in file

=head1 DESCRIPTION

B<LOGSCAN> filters log files with the intent of highlighting
"features" that may be important to the user. "Features"
refer to log information that may indicate errors or problems
indicated by the log file; however, hidden by virtue
of the volume of data frequently found in log files from
logscans such as I<Synopsys(TM)> Design Compiler.

To support a variety of log file types, B<LOGSCAN> uses
"rules" files that describe text patterns which detect the
"features". Output from B<LOGSCAN> shows line numbers and a
critical number of "context" lines preceding the features.

Novel uses of this tool include creating rulesets that check
coding conventions and light lint on source code.

=head1 OPTIONS

=over

=item B<-?>

Short help.

=item B<-banner>

Indicate PASS/FAIL status as a banner.

=item B<-c>

Specify the number of lines of context as a range
(min..max).

=item B<-d> [<FILE>]

Dump parsed rules in a compiled format (Perl) to <I<FILE>>. Default
to I<logscan.rules>. This may be used to speed up rule compilation;
although, it won't gain much performance. Log file scanning is the
most time intensive portion of B<logscan>.

=item B<-e> <I<EXTN>>

Extension (<I<EXTN>>) used for rules files. Determines filename
of rules file in conjunction with B<-k> option.
Default '.rules'.

=item B<-f> <I<FILE>>

Include file containing auxiliary rules. Use B<-k> to specify
the base rules.

=item B<-F> <I<FILE>>

Include file containing auxiliary rules if present. In other words,
unlike B<-f>, this option won't fail if the file is missing. Useful for
scripts or generic makefiles.

=item B<-h>

Display manpage and exit.

=item B<-html>

Produces an HTML formatted report for use with web browsers. This
option requires the presence of B<vim 6.0> or above and utilizes the
B<2html.vim> script in conjunction with B<logscan.vim>.

=item B<-j>

Justify rule by displaying rule number in output report. Useful if you
don't know why logscan is complaining because the message is too terse.
This will usually require dumping the ruleset to interpret (see B<-d>
option).

=item B<-INSTALL>

Simple installation.

=item B<-k> <I<KIND>>

Kind of base rules to be used. Determines filename of
rules file in conjunction with B<-e> option. Default
'default'. This option is normally specified.

=item B<-keep> <I<N>>

Maximum number of old logfiles to keep. Default 1.

=item B<-l> <I<FILE>>

Report filename to save results in. Default
I<logscan.rpt>.

=item B<-man>

Output manpage to file logscan.1 for installation
and exit.

=item B<-n>

No context, just message pointers. In other words,
don't output context and other useful information.
Useful for some editors as "tag" files.

=item B<-o> <I<FILE>>

Same as B<-l>.

=item B<-p> <I<PATH>>

Search path for rules files. Default
'/usr/local/etc:.'.

=item B<-passfail>

Indicate PASS/FAIL status textually.

=item B<-q>

Quiet (minimal runtime messages)

=item B<-tee>

Display messages to screen and logfile simultaneously.

=item B<-v>

Verbose (maximal runtime messages)

=item B<-V>

Display logscan version.

=item B<-x>

Explicit rule (should be quoted).

=item B<-X>

Exact matching -- preclude any allowances. See 'B<allow>' for more information.

=item B<-XL>

List extractable files (using B<-XT).>

=item B<-XT> <I<NAME>>

Extract <I<NAME>>d file. For installation or examples.

=back

=head1 INVOCATION EXAMPLES

 % dc_shell -f synth.dcs >synth.log
 % logscan -k synopsys synth.log

 % verilog -f rtlsim.mft -l rtlsim.log
 % logscan -k verilog -p "/usr/local/etc:../:./" \
   -F my.rules rtlsim.log

 % setenv LOGSCAN "-k ignore -p /corp/lib:/proj/lib -f drc.rules"
 % design_rule_check mydesign.data
 % logscan mydesign.err

=head1 OUTPUT DESCRIPTION

B<Logscan> outputs a minimal amount of information to the terminal
(unless you specify B<-tee>). The most import thing is the summary of
errors or warnings (message events) found. Details of the scan are
kept in the I<logscan.rpt> file. This file starts out with a
description of how the program was invoked and its version.

After the header information and parsing the rules, B<logscan> outputs
each message event with its context. The following is a sample
I<logscan.rpt> `I<error>' message:

 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 ERROR sample2.log, 19: Command failed
 Context tag is NONEMPTY
 --------------------------------------------------
 |   17|{you are here}
 |   18|find self
 :   19|{}

Each message starts out with a message separator and message
classification.  The classification includes information about the
file name and line number where the problem ocurred.

This is followed by the actual text of the message and surrounding
lines.  Lines include the line number in case you should need to look
further into this message.  The actual line where the message event was
detected in noted with a colon (:) in the first column.

=head1 RULE DESCRIPTION

Good rules make the difference between the sucessful use
of B<logscan> and failure. The following is a loose description
of the syntax for specifying rules. Hopefully, this will
be sufficient to get users started writing their own rules.
Feedback on this documentation is appreciated.

=head2 COMMENTS

Rule files should have comments embedded in them to aid
the reader in understanding what or why the rules are.
Although, rule syntax is fairly straightforward, it's not
always obvious. B<Logscan> accepts only full line comments
in any of shell, Verilog or VHDL syntaxes. Thus the following
are valid comments:

 # This is a shell style comment.
 // This is a Verilog/C++ style comment.
 -- This is a VHDL/Ada style comment.

=head2 BASIC MESSAGES

For purpose of this dicusssion, consider the following four lines
of logfile text. The trailing tilde (B<~>) marks the end of
each line.

 +---------------------------------------------------------+
 |Rythum Verilog-Excel VERSION 5.1.3~                      |
 |Some regs block in this code~                            |
 |ERROR: missing module name on line 200~                  |
 |WARNING: non-blocking and blocking assignments to reg Y.~|
 |Finish Rythum Verilog-Excel on Tue Mar 5, 2000 at 15:01~ |
 +---------------------------------------------------------+

Most B<logscan> rules have the basic syntax of:

 RULE_TYPE CONDITION PATTERN [ACTION_OR_OPTION]

Basic RULE_TYPE's are any of the keywords: 'B<fatal>', 'B<severe>',
'B<error>', 'B<warning>', 'B<alert>', 'B<note>', and 'B<info>'. These 
affect the classification of an event and the return status code.

Conditions are one of 'B<if>' or 'B<unless>'. The 'B<if>'
is the most basic condition. If the event occurs in the file
being scanned, the action will occur immediately. B<unless> handles
expectations and exceptions (discussed later).

IMPORTANT: B<unless> is a very special case used only for ensuring
items are not omitted. This feature does not work well with B<min>.

Patterns are specified in one of several manners. Which manner is
specified with one of the keywords 'B<equals>', 'B<contains>',
'B<firstword>', 'B<words>', or 'B<matches>'. B<Equals> requires
that every character in a particular line must entirely equals the
text provided. For example,

 note if equals "Rythum Verilog-Excel VERSION 5.1.3"

would look for a line that entirely equals the text between the
quotation marks and not one more or less anywhere on the line.
This matches line one (1) of our sample text.

B<Contains> allows the text to occur anywhere in the line. Thus,

 info if contains "Verilog"

matches lines 1 and 5.

B<firstword> and B<words> match only whole words. Thus,

 error if firstword "ERROR"
 warn  if words "blocking"

matches lines 1 and 3 respectively.

B<matches> is the most general form of matching and uses full
Perl regular expression syntax. Thus,

 severe if matches /DANGER:.*line \d+/

matches all lines with the string "DANGER:" following by "line " and
a number. In this example, it matches none of the sample text.

=head2 EXPECTATIONS

Expectations are an important part of log file checking. Good examples are
(1) ensuring the right version of the tool was used, and (2) ensuring the tool
exited gracefully (ie. machine didn't crash in the middle). This type of
checking is handled with the 'B<unless>' condition. Two examples corresponding
to the above illustrate this best:

 severe unless matches "Rythum Verilog-Excel VERSION 5.1.3"
 severe unless firstword "Finish Rythum Verilog-Excel" max 1

Notice the addition of the B<max>imum clause to ensure there is only
a single run. This just in case a single log file gets appended to
by multiple runs.

=head2 EXCEPTIONS

Suppose all errors are of the basic form "ERROR:"; however, the
tool reports unconnected ports as an error and for some reason
you have two unnconnected ports that are intentional (e.g. the QBAR
output of some flip-flops are unused). In this situation, you want to
catch all the errors except these two. This situation uses the
the 'B<unless>' condition combined with the B<only> clause.
For example,

 error unless matches {^ERROR:.*unconnected QBAR\b} only 2

If only two lines match this pattern, then logscan will silently
proceed; however, if there are too many or too few, then an error
will be noted. This differs from basic 'B<unless>' in that the
"too many" situation is checked on the fly and the error message may
appear if there are excess matches. This may also be accomplished
using the B<max> clause. In fact B<only> is identical to B<min N max N>.

=head2 CONTEXT

Frequently, messages in the text are only errors if the context is
appropriate. For this B<logscan> allows you to identify passages of
text that establish the different contexts using the 'B<context>' rule
and 'B<context>' clause. For example, Synopsys
Design Compiler's B<compile> command returns a line with a numeric
exit status which is 1 if successful. Thus,

 NONZERO: context if firstword "compile"
 error if equals "0" context NONZERO

Another situation might be a multiple phase log file containing
several tools' output. In this situation you could identify the
beginning text in each tool (hopefuly unique) to distiguish different
classifications of errors.

 START: context if equals "Beginning run"
 ANALYZE: context if firstword "analyze" context START
 SIMULATE: context if firstword "Simulating" context ANALYZE
 POST: context if firstword "Beginning post-processing" context SIMULATE
 FINISH: context if equals "Finished run" context POST

Notice the that context transisitions specified are orderly. Of course
this doesn't have to be the case. You must ensure that every statement
has the appropriate B<context> qualifier.

Context also causes the first name of the context to be displayed
and as many lines as possible up to the upper context line limit. This
significantly aids diagnosis of a problem. See B<-c> command-line
option or B<limit> rule.

IMPORTANT: There is only I<one> (1) active context at any point in time.
Think of it as the I<state> varaible of a finite state machine. You
can change it dependently or not (e.g. reset might be independent).

Finally, there is a 'B<goto>' qualifier that can be used to change context
in conjunction with informational messages. This avoids having both an
B<info> and a B<context> rule for the same pattern, and improves execution
performance.

 info if firstword "Entering second stage" context STAGE1 goto STAGE2

=head2 CLAUSES

Use of the 'B<and>' qualifier permits additional requirements in the
form of expressions computed on subfields of the matching expression.
For instance, you might allow several versions of a tool to be used
as long as they are greater than a particular one:

 error unless matches {Version (\d+\.\d+)} and {=$1 > 2.3=}

Expression must be enclosed in B<{=> B<=}> and conform to Perl requirements.
Additionally, the variables B<$&>, B<$+>, B<$1>, B<$2>, B<$3>, B<$4>, B<$5>, 
and B<$6> are available.

=head2 ALLOWANCES

Use of the 'B<allow>' qualifier permits so called "soft matching" based on
expressions computed on subfields of the matching expression. For example,
you may wish to ignore the time stamp in a simulation most of the time,
but want to know if it changed when issuing an exception:

 error unless matches {WARNING at time (\d+ ns): counter cleared} allow {=$1 eq "52 ns"=}

Expression must be enclosed in B<{=> B<=}> and conform to Perl requirements.
Additionally, the variables B<$&>, B<$+>, B<$1>, B<$2>, B<$3>, B<$4>, B<$5>, 
and B<$6> are available.

=head2 CONTROLLING CONTEXTS

By using the B<enable> and B<disable> clauses, you can also turn a
set of context controlled rules on and off. This allows you suspend
error messages for a certain portion of the file.

 enable  USER_MESSAGES if contains "Start user messages" 
 disable USER_MESSAGES if contains "End user messages" 

=head2 CUSTOM MESSAGES

By default, B<logscan> will display error messages indicating
the failing pattern; however, you may specify your own message
to accompany any failures or info using the 'B<msg>' clause.

 error if words "CRC error" msg "Found Cyclic Redundancy Check error"

Additionally, messages may contain references to some special "variables"
and custom variables. Special variables include:

=over

=item B<$&>

the matching text

=item B<$1>

matching text inside the 1st parenthesis pair

=item B<$2>

matching text inside the 2nd parenthesis pair

=item B<$3>

matching text inside the 3rd parenthesis pair

=item B<$4>

matching text inside the 4th parenthesis pair

=item B<$5>

matching text inside the 5th parenthesis pair

=item B<$6>

matching text inside the 6th parenthesis pair

=item B<$tag>

name of the rule (hopefully a unique tag label)

=item B<$typ>

type of rule (e.g. 'error' or 'warn')

=item B<$cmp>

comparison type

=item B<$pat>

pattern being searched for

=item B<$cnt>

number of times matched

=item B<$CNT>

pluralized number of times matched

=item B<$max>

maximum requirement

=item B<$min>

minimum requirement

=item B<$RNG>

expected range (min .. max)

=back

An example of usage might be:

 CHECK1: error if matches {^Total of (\d+) failing packets} \
   and {= $1 != $expected =} \
   msg "Failed $1 packets out of $expected in $tag"

=head2 OTHER CONTROLS

A few other controls are available to help control logscan and
interpret the results.

The 'B<echo>' rule simply outputs text during rule parsing. Use
this to output a title for the rules and the version.

 echo "Rythum simulation rules version 1.2"

Use the 'B<limit>' rule to control B<logscan>'s context buffer.
Perhaps you want to have at least three (3) lines of context, but
no more than ten.

You may include other rules files either during parsing or on-the-fly
with one of the rules 'B<use>', 'B<require>' or 'B<use>'. The 'B<use>'
also resets all the rules. This is an alternate way to accomplish
major tool context switches. At the end of a tool's output you could
switch to a default rules set that attempts to figure out where to go
next. Thus,

 use "default.rules" if equals "Finished."

 use "dcshell.rules" if contains "Design-Compiler"
 use "verilog.rules" if contains "Verilog-XL"
 use "vcs.rules" if contains "Synopsys VCS"

Use the 'B<version>' rule to require a specific version of B<logscan>.

Use B<verbose> or B<quiet> respectively to increase or decrease the
amount of information sent to STDOUT. All information is recorded in
the log file.

You may also specify B<logsan>'s logfile name with the 'B<log>' rule.

=head2 NAMES

If you don't like the keywords supplied by logscan, you can supply
your own in the form of aliases. This might be useful for foreign
languages too. There are some predefined aliases too. For example,

 alias firstwords=firstword

=head2 CONTROLLING RULES

It is possible to disallow or reset entire classifications of rules (i.e.
RULE_TYPE's. Once disallowed, a keyword can never be reallowed;
however, if you setup an alias it is possible to use the alias. An
administrator might use this capability.

=head2 USING CALCULATIONS

Sometimes it is necessary to gather statistics and make error judgements
at the end. This is accomplished using the B<eval> clause in conjunction
with the B<unless expr> operation.

 count if matches {ERROR: CRC discarded (\d+) blocks of (\d+) bytes} \
      eval {= $my_count += $1 * $2 =}

 # Following takes place after entire file scanned
 error unless expr expr {= $my_count != 15 =} \
      msg "Discarded $my_count rather than 15 expected"

Note that the B<eval> clause behaves slightly differently for B<if> vs. 
B<unless expr> operations. In the former, B<eval> is executed only when the
condition is true, but for B<unless expr> the B<eval> is executed unconditionally.

=head2 FINAL THOUGHTS

Use the B<post> condition to issue messages unconditionally after processing. This
is useful to display the results of calculations.

 info post msg "Saw $crc_count CRC blocks"

=head1 RULE SYNTAX

The following is the concise syntax of rule for logscan. Rules are
contained in one or more files that are specified either on the
command line (via B<-k>, B<-f> or B<-F>) or via other rule files
invoking them (via B<use>, B<require> or B<include> statements).

Rules are read in REVERSE order of presentation to allow local
overrides.

Rules are restricted to a single line unless the last character of the
line is a backslash '\' or in the middle of a multi-line SCAN_PATTERN.
See RULE DESCRIPTION and RULE EXAMPLES for clarification.

 #  COMMENT
 // COMMENT
 -- COMMENT
 [<TAG>:] <RULE_TYPE> if     <RULE_EXPRESSION> <RULE_CLAUSE>..
 [<TAG>:] <RULE_TYPE> unless <RULE_EXPRESSION> <RULE_CLAUSE>..
          <RULE_TYPE> post   <RULE_CLAUSE>..
 [<TAG>:] enable|disable <TAG_PATTERN> [if <CLAUSE>]
 define NAME TEXT
 disallow|clear <RULE_TYPE>[s]
 use|require|include <FILE>
 echo <TEXT>
 version <NUMBER>
 quiet
 verbose
 log <FILE>
 limit <NUMBER>..<NUMBER>
 alias <NEW>=<OLD>

NOTE: B<if> is processed only during scanning. B<unless expr> and
B<post> are processed only after scanning. Other B<unless> are
examined both during and after.

=head2 RULE TYPES

 NAME    RETURN  ACTION
 ----    ------  ------
 fatal   128     message & exit program
 severe  64..127 message & next line
 error   1..63   message & next line
 warning 0       message & next line
 alert   0       message (considered a warning)
 note    0       message & next line
 info    0       message (considered a note)
 count   0       count
 ignore  0       next line
 context -       load context register with line <TAG>
 require -       append rules
 include -       append rules if found
 use     -       read new set of rules

=head2 RULE EXPRESSIONS

 equals    {ENTIRE_LINE}
 contains  {TEXT}
 firstword {WORD}
 words     {WORD...WORD}
 matches   {PERL_REGULAR_EXPRESSION}
 expr      {PERL_EXPRESSION} 

NOTE 1: B<{}> may be replaced with any pair of (), [], <> or 
simple "", '', //.

NOTE 2: TEXT or EXPRESSION may extend over multiple lines (be careful).

NOTE 3: ('=', '?', '~') may be used instead of ('equals', 'contains', 'matches') respectively.

NOTE 4: B<expr> is only valid in conjunction with B<unless>.

=head2 RULE CLAUSES

 allow {=EXPR=}         allows Perl EXPR to be false, but notes it
 eval  {=EXPR=}         evaluates Perl EXPR
 and {=EXPR=}           additional constraint based on evaluation of Perl EXPR
 context <TAG_PATTERN>  context must match <TAG_PATTERN> 
 goto <TAG>             changes context to specified <TAG> 
 enable <TAG_PATTERN>   enable tagged rules matching <TAG_PATTERN>
 disable <TAG_PATTERN>  disable tagged rules matching <TAG_PATTERN>
 msg <TEXT>             display <TEXT>
 only <NUMBER>          minimum and maximum occurence of <NUMBER> times
 min <NUMBER>           must appear at least <NUMBER> times to be considered
 max <NUMBER>           ignored if appears more than <NUMBER> times
 show <NUMBER>[ more[ lines]]
 always                 force additional interpretation

=head2 RULE NOTES

Rules are read in REVERSE order.

Because rules are interpreted strictly in the order encountered, and
because rule of class: {severe, error, warning, note, info, &
ignore} cause immediate skipping to the next line in the log file,
special care should be taken when applying these rules in case they
might disable a 'context' rule.

As a potential mechanism to ensure contexts or other important rules,
the 'always' clause may be added to force a rule's interpretation
even if was indicated to be skipped. This option is powerful, and
equally as dangerous in the reverse sense.

'B<use>' resets the rules (ie. clears out all patterns) & must exist

'B<require>' must find the specified file

'B<include>' merely adds to the rule set (ie. no complaints about
missing files)

TEXT and EXPR may reference $&, $+, $1, $2, $3, $4, $5, and $6 which
work as in Perl.  For example, refers to the first matched text in
parentheses.  These only work for 'matches' (ie. regular expression)
patterns.

=head1 RULE EXAMPLES

 my.rules
 +-----------------------------------------------------------------+
 |# The following are some typical rules used with Synopsys        |
 |  verbose                                                        |
 |  # First setup contexts                                         |
 |  NONZERO: context if firstword "compile"                        |
 |  NONZERO: context if firstword "link"                           |
 |  KEYWORD: context if firstword "if"                             |
 |  KEYWORD: context if firstword "while"                          |
 |  KEYWORD: context if contains  "} else {"                       |
 |  # Now handle the errors associated with contexts               |
 |  error if matches /^0\$/  msg "Command failed" context NONZERO  |
 |  error if matches /^{}\$/ msg "Command failed" context NONEMPTY |
 |  # Handle errors of a more general nature                       |
 |  severe if matches /^ABORT\b/                                   |
 |  warn  if firstword "WARNING" msg "User warning detected";      |
 |  error if firstword "ERROR" msg "User error detected";          |
 |  error if contains "latch inferred" show 2 more lines           |
 |  info if matches /inferred (\d+)/ and {=\$1>9=}                 |
 |  # Following illustrates various multi-line features            |
 |  REVCHECK: \                                                    |
 |    error unless matches {.*rev\. 5.1                            |
 |\s+15 Dec} msg "Must use rev \$1." \                             |
 |           disable REVCHECK                                      |
 |  # Finally add the exceptions                                   |
 |  ignore if words "No latch inferred"                            |
 |  # - require 2 latches                                          |
 |  error unless matches {latch inferred} only 2                   |
 +~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+

=head1 ENVIRONMENT

B<LOGSCAN> contains command line options that are interpreted
prior to parsing the command line.


=head1 FILES

Rules files are selected two different ways. First, an
path is searched for files of the name <I<KIND>>.<I<EXTN>>. The
default path, basename, and filename extension may be
changed with the B<-p>, B<-k>, and B<-e> command line options.

=head1 BUGS

None known

=head1 NOTES

The sanity counter outputs a character every 15 seconds
unless B<-q> (quiet) is in effect.

B<LOGSCAN> may be under the GPL via the Internet at
URL: <http://www.hldwizard.com/logscan.tar.gz>

=head1 AUTHOR

David C. Black <dcblack@hldwizard.com>

=head1 COPYRIGHT

Copyright (C) 1997-2001,2008 by David C. Black
<dcblack@hldwizard.com> All rights reserved.

=head1 LICENSE

This software, B<logscan>, is CharityWare in the manner of Bram Moolenaar's vim
text editor (Vi IMproved). You may use and copy it as much as you like, but
you are encouraged to make a donation to a non-profit charity organization
addressing poverty-hunger, poverty-housing, or racial justice. Payment should
be made directly to the charity of your choice. Please extract the LICENSE
details using the command: logscan -XT LICENSE.

Redistribution and in source and binary forms are permitted provided that the
above copyright notice and license are duplicated in all such forms and that
any documentation, advertising materials, and other materials related to such
distribution and use acknowledge that the software was developed by David C.
Black, High Level Design Wizard. <http://www.hldwizard.com>

There are no restrictions on distributing an unmodified copy of Logscan. Parts
of Logscan may also be distributed, but this text must always be included. You
are allowed to include executables that you made from the unmodified Logscan
sources, your own usage examples and Logscan scripts.

If you distribute a modified version of Logscan, you are encouraged to send
the maintainer a copy, including the source code. Or make it available to the
maintainer through ftp; let him know where it can be found. If the number of
changes is small (e.g., a modified Makefile) e-mailing the diffs will do.
When the maintainer asks for it (in any way) you must make your changes,
including source code, available to him. The e-mail address to be used is
<maintainer@hldwizard.com>

The maintainer reserves the right to include any changes in the official
version of Logscan. This is negotiable. You are not allowed to distribute a
modified version of Logscan when you are not willing to make the source code
available to the maintainer.

It is not allowed to remove these restrictions from the distribution of the
Logscan sources or parts of it. These restrictions may also be used for
previous Logscan releases instead of the text that was included with it.

THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

Never-the-less, you are encouraged to send bug reports to me, David C Black
<dcblack@hldwizard.com>. Registered users may expect some support for severe
bugs as determined by me. Enhancements and/or feature requests will be noted;
however, no commitments will be made. There are no guarantees that response
will be timely. Please include the word B<LOGSCAN> in the Subject header of
your email.

=head1 VERIFICATION

All valid releases of this logscan are accompanied with a PGP signature file
logscan.pgp to verify you have an unmodified copy. Also, the license file may
be extracted as a PGP signed document.

=cut

#############################################################################

   #========================================================================
   # Initializations
   #------------------------------------------------------------------------
   &Initialize;
    
   $banner = sprintf("\n%s %s\n%s",$tool,$revs,&VersionBanner);

   #========================================================================
   # Process command line arguments
   #------------------------------------------------------------------------
   &Process_Command_Line;
    
   &Error("No input file to scan!?") unless @INPUT_FILES or defined $only_rules;

   #========================================================================
   # Read the rules
   #------------------------------------------------------------------------
   &Read_Rules;
    
   # Check to see if user specified -k, -f or -F and whether any rules
   # were read.
   if (scalar @RULE_LOL == 0) {
      &Error("No rules of any kind read/specified!?");
   } elsif ($rules_read == 0) {
      &Warn("No -k $KIND$EXTN rules read!?");
   }#endif
   if ($only_rules) {
      &Dump_Rules($DUMP_FILE,$only_rules);
      &Exit(1);;
   }#endif
    
   #========================================================================
   # Process the log files
   #------------------------------------------------------------------------
   &Process_Log_Files ;

   #======================================================================
   # Output overall statistics summary
   #----------------------------------------------------------------------
   &Printf2BothIfTee("%s\n",$sep1 x $SW);
   foreach $typ (@STAT) {
      #next unless defined $STAT{$typ};
      &Printf2Both("Found total of %s\n", &Plural($STAT{$typ},$typ,-2),-1,0,1);
   }#endforeach $typ
   my $pass = &Exit_Status ? 'FAILED' : 'PASSED';
   &Printf2Both("%s %s\n",$Tool, $pass) if defined $OPT_passfail;
   if (defined $OPT_banner) {
      &Printf2Both("%s\n\n",($sep1 x $SW)); # separator
      system "banner $pass";
   }#endif
   &Printf2Both("%s\n",($sep1 x $SW)); # separator
   &Printf2Both("Exit status %d (0x%x)\n", &Exit_Status, &Exit_Status);
    
   &Exit(&Exit_Status);
    
   die("PANIC: How did we get here?");

#############################################################################
BEGIN {

#############################################################################
sub Quiet { ($verbosity eq 'quiet'); }

#############################################################################
sub Verbose { ($verbosity eq 'very'); }

#############################################################################
sub Writable {
   my ($path) = @_;
   my $dir = $path;
   if ($path =~ m:/:) {
      $dir =~ s:/[^/]+$::;
   } else {
      $dir = '.';
   }#endif
   return (-w $path or (-w $dir and ! -e $path));
}#endsub Writable

#############################################################################
sub Create_Rpt {
   my ($file) = @_;
   $file = "$tool.rpt" if $file eq '';
   ($file) = &Keep($file);
   &Die("Unable to write to $file.") unless &Writable($file);
   if ($logfile) {
      print STDOUT "Closing logfile $logfile\n" unless &Quiet;
      close RPTFILE;
      unlink $file if -e $file;
      rename $logfile,$file;
      $logfile = '';
      open(RPTFILE,">>$file") or &Die("Couldn't write to $file");
      RPTFILE->autoflush(1);
      $logfile = $file;
      printf STDOUT "Logging to %s\n",$file unless &Quiet;
      select(RPTFILE);
      $|=1;
      select(STDOUT);
   } else {
      open(RPTFILE,">$file") or &Die("Couldn't write to $file");
      RPTFILE->autoflush(1);
      $logfile = $file;
      select(RPTFILE);
      $|=1;
      select(STDERR);
      $|=1;
      select(STDOUT);
      $|=1;
      printf STDOUT "Logging to %s\n",$file unless &Quiet;
      &Printf2Log("#%s\n",'-' x $SW);
      &Printf2Log("# Tool: %s version %s\n",$TOOL,$revs);
      &Printf2Log("# Date: %s\n",$when);
      &Printf2Log("# %% setenv LOGFILE '%s'\n",$ENV{$TOOL}) if defined $ENV{$TOOL};
      &Printf2Log("# %% telnet -l %s %s\n",$user,$host);
      &Printf2Log("# %% cd %s\n",$wd);
      &Printf2Log("# %% %s %s\n",$tool,join(' ',@ORIG));
      &Printf2Log("#%s\n",'-' x $SW);
      &Printf2Log("\nRULE_PATH: %s\n\n",join(':',@RULE_PATH));
   }#endif
}#endsub Create_Rpt

#############################################################################
sub Printf2Log {
   &Create_Rpt() unless defined $logfile;
   my($format,@values) = @_;
   if ($format =~ m/^[?][?]/) {
      $format = substr($format, 3, -1);
      $format = "\n" . $format if $needLF;
   }#endif
   if ($format eq '') {
      $format = "\n";
   } #endif
   $format = sprintf($format,@values);
   $needLF = (substr($format,-1,1) ne "\n");

   print RPTFILE $format;
}#endsub Printf2Log

############################################################################
sub Printf2Both {
   my ($format, @values) = @_;
   if ($crazy and defined $tee) {
      print("\n");
      $crazy = 0;
   }#endif
   printf($format,@values) unless &Quiet;
   &Printf2Log($format,@values);
}#endsub Printf2Both

############################################################################
sub Printf2BothIfTee {
   my ($format, @values) = @_;
   if ($crazy and defined $tee) {
      print("\n");
      $crazy = 0;
   }#endif
   printf($format,@values) if defined $tee and ! &Quiet;
   &Printf2Log($format,@values);
}#endsub Printf2BothIfTee

#############################################################################
sub min {
   my $min = $_[0];
   foreach (@_) {
      $min = $_ if $_ < $min;
   }#endforeach
   return $min;
}#endsub min

#############################################################################
sub max {
   my $max = $_[0];
   foreach (@_) {
      $max = $_ if $_ > $max;
   }#endforeach
   return $max;
}#endsub max

#############################################################################
sub Prepare {
   my ($pSUBST, $pstr, $pattern, $replacement) = @_;
   my $i = scalar @$pSUBST;
   while ($$pstr =~ s/$pattern/\001$i\002/) {
      push @$pSUBST,$replacement;
   }#endwhile
}#endsub Prepare

sub Substitute {
   my ($pSUBST, $pstr) =@_;
   my ($i, $replacement);
   for $i (0..$#{$pSUBST}) {
      $replacement = $pSUBST->[$i];
      $$pstr =~ s/\001$i\002/$replacement/;
   }#endfor
}#endsub Substitute

#############################################################################
sub Info {
   my ($iRULE,$tag,$typ,$cnd,$msg,$ctx,$sho,$file,$line,$cmp,$pat,$cnt,$min,$max,@text)=@_;
   my $CND = 'expected';
   my $CNT = &Plural($cnt,'time',-2,'',1);
   my $RNG = ($min > 0 and $min == $max) ? "$min"
         : ($min > 0 and $max > 0)     ? "$min to $max"
         : ($min > 0)                  ? "min $min" 
         : ($max > 0)                  ? "max $max"
         :                               "?";
   my @SUBST = ();
   &Prepare(\@SUBST, \$msg, q/[\$][&]/, $text[0]);
   &Prepare(\@SUBST, \$msg, q/[\$][+]/, $text[1]);
   &Prepare(\@SUBST, \$msg, q/[\$][1]\b/, $text[2]);
   &Prepare(\@SUBST, \$msg, q/[\$][2]\b/, $text[3]);
   &Prepare(\@SUBST, \$msg, q/[\$][3]\b/, $text[4]);
   &Prepare(\@SUBST, \$msg, q/[\$][4]\b/, $text[5]);
   &Prepare(\@SUBST, \$msg, q/[\$][5]\b/, $text[6]);
   &Prepare(\@SUBST, \$msg, q/[\$][6]\b/, $text[7]);
   &Prepare(\@SUBST, \$msg, q/\$tag\b/,   $tag);
   &Prepare(\@SUBST, \$msg, q/\$typ\b/,   $typ);
   &Prepare(\@SUBST, \$msg, q/\$CND\b/,   $CND);
   &Prepare(\@SUBST, \$msg, q/\$CNT\b/,   $CNT);
   &Prepare(\@SUBST, \$msg, q/\$RNG\b/,   $RNG);
   &Prepare(\@SUBST, \$msg, q/\$pat\b/,   $pat);
   &Prepare(\@SUBST, \$msg, q/\$cmp\b/,   $cmp);
   &Prepare(\@SUBST, \$msg, q/\$cnt\b/,   $cnt);
   &Prepare(\@SUBST, \$msg, q/\$min\b/,   $min);
   &Prepare(\@SUBST, \$msg, q/\$max\b/,   $max);
   my (@repl);
   if ($msg =~ m/[\$][{]?[A-Za-z][}]?/) {
      while ($msg =~ s/[\$]([A-Za-z]\w*)/\003/ or $msg =~ s/[\$]{([A-Za-z]\w*)}/\003/) {
         push @repl, $main::VAR{$1};
      }#endwhile
   }#endif
   &Substitute(\@SUBST, \$msg);
   if ($msg =~ m/\003/) {
      my $repl;
      for $repl (@repl) {
         $msg =~ s/\003/$repl/;
      }#endfor
   }#endif
   $msg =~ s/^./\u$&/;
   &Printf2BothIfTee("\n%s\n",($sep1 x $SW)); # separator
   &Printf2BothIfTee("%s %s, %s: %s\n",uc($typ),$file,$line,$msg); # summary line
   &Printf2BothIfTee("Context tag is %s\n",$CONTEXT_TAG) if $ctx and $CONTEXT_TAG ne '' and !defined $message_only;
   &Printf2BothIfTee("%s\n",&Show_Rule($iRULE)) if $OPT_justify;
   &Printf2BothIfTee("%s\n",($sep2 x $SW)); # separator
}#endsub Info

#############################################################################
sub Message {
   my ($iRULE,$tag,$typ,$cnd,$msg,$ctx,$sho,$file,$line,$cmp,$pat,$cnt,$min,$max,@text)=@_;
   #Debug(0x0020,"MESSAGE($typ,$cnd,$cmp) -> $msg");
   my $CND = 'expected';
   my $CNT = &Plural($cnt,'time',-2,'',1);
   my $RNG = ($min > 0 and $min == $max) ? "$min"
         : ($min > 0 and $max > 0)     ? "$min to $max"
         : ($min > 0)                  ? "min $min" 
         : ($max > 0)                  ? "max $max"
         :                               "?";
   if ($line eq '' and ($min ne '' and $cnt < $min) or ($max ne '' and $cnt > $max)) {
      $msg = 'Found $CNT vs $RNG in expected pattern {$pat} - $tag';
   } elsif ($line eq '' and $typ eq 'count') {
      $CNT = &Plural($cnt,'occurrence',-2,'',1);
      if      ($cmp eq 'equals') {
         $msg = 'Found $CNT of exact line "$pat"';
      } elsif ($cmp eq 'contains') {
         $msg = 'Found $CNT of string "$pat"';
      } elsif ($cmp eq 'firstword') {
         $msg = 'Found $CNT starting with "$pat"';
      } elsif ($cmp eq 'matches') {
         $msg = 'Found $CNT matching m{$pat}';
      }#endif
   } elsif ($line eq '' and $msg eq '') {
      $msg = 'Failed $tag';
   }#endif
   my @SUBST = ();
   &Prepare(\@SUBST, \$msg, q/[\$][&]/, $text[0]);
   &Prepare(\@SUBST, \$msg, q/[\$][+]/, $text[1]);
   &Prepare(\@SUBST, \$msg, q/[\$][1]\b/, $text[2]);
   &Prepare(\@SUBST, \$msg, q/[\$][2]\b/, $text[3]);
   &Prepare(\@SUBST, \$msg, q/[\$][3]\b/, $text[4]);
   &Prepare(\@SUBST, \$msg, q/[\$][4]\b/, $text[5]);
   &Prepare(\@SUBST, \$msg, q/[\$][5]\b/, $text[6]);
   &Prepare(\@SUBST, \$msg, q/[\$][6]\b/, $text[7]);
   &Prepare(\@SUBST, \$msg, q/\$tag\b/,   $tag);
   &Prepare(\@SUBST, \$msg, q/\$typ\b/,   $typ);
   &Prepare(\@SUBST, \$msg, q/\$CND\b/,   $CND);
   &Prepare(\@SUBST, \$msg, q/\$CNT\b/,   $CNT);
   &Prepare(\@SUBST, \$msg, q/\$RNG\b/,   $RNG);
   &Prepare(\@SUBST, \$msg, q/\$pat\b/,   $pat);
   &Prepare(\@SUBST, \$msg, q/\$cmp\b/,   $cmp);
   &Prepare(\@SUBST, \$msg, q/\$cnt\b/,   $cnt);
   &Prepare(\@SUBST, \$msg, q/\$min\b/,   $min);
   &Prepare(\@SUBST, \$msg, q/\$max\b/,   $max);
   my (@repl);
   if ($msg =~ m/[\$][{]?[A-Za-z][}]?/) {
      while ($msg =~ s/[\$]([A-Za-z]\w*)/\003/ or $msg =~ s/[\$]{([A-Za-z]\w*)}/\003/) {
         push @repl, $main::VAR{$1};
      }#endwhile
   }#endif
   &Substitute(\@SUBST, \$msg);
   if ($msg =~ m/\003/) {
      my $repl;
      for $repl (@repl) {
         $msg =~ s/\003/$repl/;
      }#endfor
   }#endif
   $msg =~ s/^./\u$&/;
   if ($line eq '') { # this is a requirement (ie. missing line)
      if (not $startedpost) {
         &Printf2BothIfTee("\n%s\n",($sep1 x $SW)); # separator
         &Printf2BothIfTee("Post processing messages:\n");
         &Printf2BothIfTee("%s\n",($sep1 x $SW)); # separator
         $startedpost = 1;
         &Debug(0x0080,"MESSAGE %VARS = (\n".&Dump_Vars.");");
      }#endif
      &Printf2BothIfTee("%s %s, %s: %s\n",uc($typ),$file,$line,$msg); # summary line
   } else { # line with an error
      if ($sho or $show_min) {
         # pull in $sho lines of additional context
         for (1..&max($sho,$show_min)) {
            &Next_Sho_Line;
         }#endfor
      }#endif
      &Printf2BothIfTee("\n%s\n",($sep1 x $SW)); # separator
      &Printf2BothIfTee("%s %s, %s: %s\n",uc($typ),$file,$line,$msg); # summary line
      &Printf2BothIfTee("Context tag is %s\n",$CONTEXT_TAG) if $ctx and $CONTEXT_TAG ne '' and !defined $message_only;
      &Printf2BothIfTee("%s\n",&Show_Rule($iRULE)) if $OPT_justify;
      &Printf2BothIfTee("%s\n",($sep2 x $SW)); # separator
      #--------------------------------------------------------------------
      # show context
      $FW = 6;
      my $fmt = "%s %${FW}d|%s\n";
      my $etc = "| %-${FW}.${FW}s| omitted lines\n";
      my ($context_index, $context_line, $context_last, $delta);
      $context_last = $#CONTEXT_BUF;
      if ($context_last < $max_context) { # not too many lines in @CONTEXT_BUF buffer
         $context_index = 0;
         $context_line = $line - $context_last;
      } else { # more than enough lines in @CONTEXT_BUF buffer
         $context_index = $context_last - $max_context;
         $context_line = $line - $max_context;
      }#endif
      if ($CONTEXT_TXT ne '') { # there is special context
         if ($context_line > $CONTEXT_LNO) { # context MISSING from @CONTEXT_BUF buffer
            &Printf2BothIfTee($fmt,'|',$CONTEXT_LNO,$CONTEXT_TXT);
            &Printf2BothIfTee($etc,'.' x 6);
         } else { # context FOUND in @CONTEXT_BUF buffer
            $delta = $CONTEXT_LNO - $context_line;
            $context_index += $delta;
            $context_line += $delta;
         }#endif
      }#endif
      # Make sure we get the minimum context or as much as possible
      $delta = &max( 0, $context_last - $min_context );
      if ($context_index > $delta) {
         $delta = $context_index - $delta;
         $context_index -= $delta;
         $context_line  -= $delta;
      }#endif
      my $bar;
      while ($context_index <= $context_last) {
         $bar = ($context_line == $line) ? ':' : '|';
         &Printf2BothIfTee($fmt,$bar,$context_line,$CONTEXT_BUF[$context_index]);
         $context_index++;
         $context_line++;
      }#endfor
      if (&max($sho,$show_min) > 0) {
         my ($show_index,$show_line);
         for $show_index (0..&min(&max($sho,$show_min)-1,$#SHOWN)) {
            $show_line = $SHOWN[$show_index];
            &Printf2BothIfTee($fmt,'|',$context_line + $show_index,$SHOWN[$show_index]);
         }#endfor
      }#endif
      # Flush context (ie. minimize output)
      @CONTEXT_BUF = ();
   }#endif
   &Printf2BothIfTee("\n") unless $line eq '';
}#endsub Message

#############################################################################
sub Debug {
   my ($LEVEL,@ARGS) = @_;
   return unless ($DEBUG & $LEVEL) and ($DEBUG & 0x800) ? ($DEBUG == $LEVEL) : 1;
   $| = 1;
   my $fmt;
   $fmt = (@ARGS > 1 and index($ARGS[0],'%') >= 0) ? shift(@ARGS) : '%s';
   @ARGS = (join(' ',@ARGS)) if $fmt eq '%s' and @ARGS > 1;
   my $msg=sprintf("<<DEBUG $TOOL>>  $fmt",@ARGS);
   chomp($msg);
   &Printf2Both("%s\n",$msg);
}#endsub Debug

#############################################################################
sub Emsg {
   my ($TYPE,@ARGS) = @_;
   my $fmt;
   $fmt = (@ARGS > 1 and index($ARGS[0],'%') >= 0) ? shift(@ARGS) : '%s';
   @ARGS = (join(' ',@ARGS)) if $fmt eq '%s' and @ARGS > 1;
   my $WHERE = defined $RULE_FILE ? " $RULE_FILE, line $RULE_LNO" : '';
   printf STDERR "$TYPE(%s)%s: $fmt\n",$tool,$WHERE,@ARGS;
   &Printf2Log("$TYPE(%s)%s: $fmt\n",$tool,$WHERE,@ARGS);
}#endsub Emsg

#############################################################################
sub Die {
   &Emsg('DIE',@_);
   exit 128;
}#endsub Die

#############################################################################
sub Fatal {
   &Emsg('FATAL',@_);
   exit 128;
}#endsub Fatal

#############################################################################
sub Error {
   &Emsg('ERROR',@_);
   $STAT{'errors'}++;
}#endsub Error

#############################################################################
sub Warn {
   &Emsg('WARNING','%s',@_);
   $STAT{'warning'}++;
}#endsub Warn

#############################################################################
sub file2html {
   for my $file (@_) {
      &Keep("$file.html");
      exec "vim -c 'runtime! syntax/2html.vim' -c xa $file";
   }#endfor
}#endsub rpt2html

#############################################################################
sub Exit {
   my ($Exit_Status) = @_;
   if ($logfile) {
      close(RPTFILE);
      &file2html($logfile) if $OPT_html;
   }#endif
   if (defined $INTERNAL) {
#        my (@internal_files) = sort keys %internal_files;
#        my $internal_dir = "/tmp";
#        my ($user) = getpwuid($<);
#        my ($tarfile) = &Keep("$internal_dir/$tool.$host.$user.tar");
#        system(sprintf("tar cf $tarfile %s",@internal_files));
#        system("echo 'Internal files in $tarfile' >>$logfile") if ($logfile);
   }#endif
   exit ($Exit_Status);
}#endsub Exit

#############################################################################
sub Handler { # 1st argument is signal name
   my($sig) = @_;
   Error "Caught a SIG$sig--shutting down\n";
   &Printf2Log("ABORT: Caught a SIG%s--shutting down\n",$sig);
   &Exit(128);
}#endsub Handler

#############################################################################
sub Handler2 { # 1st argument is signal name
   my($sig) = @_;
   Error "Caught a SIG$sig\n";
   &Printf2Log("INFO: Caught a SIG%s\n",$sig);
   $request = $sig;
   &Dump_Rules('debug.rules') if $debug_dump;
}#endsub Handler2

#############################################################################
sub Plural {
   my ($how_many,$phrase,$case,$paren,$maxword,$ord) = @_;
   # $how_many = number to be converted
   # $phrase = word to be pluralized
   # $case = (-2,-1,0,1,2) = (phrase,forcelower,untouched,forceupper,sentence)
   # $paren = add parenthesized number after word (default yes)
   # $maxword = maximum $how_many to use as a word
   # $ord = use ordinal numbering vs cardinal
   $maxword = 99 unless defined $maxword || $maxword > 99;
   $paren = 1 unless defined $paren;
   $paren = sprintf(' (%d)',$how_many) if $paren;
   my $result = '';
   my $negative = $how_many < 0 ? 'negative ' : '';
   $how_many = -$how_many if $negative;
   my (@nos)=qw(
      Zero        One         Two         Three      Four       Five
      Six         Seven       Eight       Nine       Ten        Eleven
      Twelve      Thirteen    Fourteen    Fifteen    Sixteen    Seventeen
      Eighteen    Nineteen    Twenty      Thirty     Forty      Fifty
      Sixty       Seventy     Eighty      Ninety     Hundred    Thousand

      Zeroth      First       Second      Third      Fourth     Fifth
      Sixth       Seventh     Eighth      Ninth      Tenth      Eleventh
      Twelfth     Thirteenth  Fourteenth  Fifteenth  Sixteenth  Seventeenth
      Eighteenth  Nineteenth  Twentieth   Thirtieth  Fortieth   Fiftieth
      Sixtieth    Seventieth  Eightieth   Ninetieth  Hundredth  Thousandth
   );
   if ($ord == 0) { # Cardinal
      if ($how_many == 1 && $how_many <= $maxword) {
         $result = "$negative$nos[$how_many]$paren ${phrase}";
      } elsif (($how_many % 100) < 20 && $how_many <= $maxword) {
         my $twenty = $nos[$how_many % 20];
         $result = "$negative$twenty$paren ${phrase}s";
      } elsif (20 <= ($how_many % 100) && $how_many <= $maxword) {
         my $tens = int($how_many % 100 / 10) + 18;
         my $ones = ($how_many % 10) ? ('-'.$nos[$how_many % 10]) : '';
         $result = $negative.$nos[$tens].$ones.$paren." ${phrase}s";
      } else {
         $result = "$negative$how_many$paren ${phrase}s";
      }#endif
   } else { # Ordinal
      if (($how_many % 100) < 20 && $how_many <= $maxword) {
         my $twenty = $nos[30 + $how_many % 20];
         $result = "$negative$twenty$paren ${phrase}";
      } elsif (20 <= ($how_many % 100) && $how_many <= $maxword) {
         my $tens = int($how_many % 100 / 10) + 18 + (($how_many % 10) ? 0 : 30);
         my $ones = ($how_many % 10) ? ('-'.$nos[30 + $how_many % 10]) : '';
         $result = $negative.$nos[$tens].$ones.$paren." ${phrase}s";
      } else {
         $result = "$negative${how_many}th$paren ${phrase}";
      }#endif
   }#endif
   $result = lc($result) if $case == -1;
   $result = uc($result) if $case ==  1;
   $result =~ s/^./\l$&/ if $case == -2;
   $result =~ s/^./\u$&/ if $case ==  2;
   return $result;
}#endsub Plural

#############################################################################
# Return a string describing the version extracted from the RCS Id field.
sub RcsVersion {
   my ($vers) = @_;
   my (@info) = split(' ',$vers);
   #------------------------------------------------------------------------
   # Figure out the full "official version" number
   #------------------------------------------------------------------------
   my $revn = $info[2];
   my $base = $main::offl;
   $base =~ s/^\d+\.//;
   $revn =~ s/^\d+\.//;
   my $diff = $revn - $base;
   $diff = $revn if $diff < 0;
   $revn = $main::offl.'.'.$diff;
   my (%aka) = (
      'exp'  => 'proto',
      'rel'  => 'released',
      'rlsd' => 'released',
   );
   #------------------------------------------------------------------------
   # Now compute the state
   #------------------------------------------------------------------------
   my $state = lc($info[6]);
   $state = $aka{$state} if defined $aka{$state};
   $state = 'released' if $diff == 0;
   $info = "$revn ($state)";
   return $info;
}#endsub RcsVersion

############################################################################
sub Box {
   my ($msg,$border,$center) = @_;
   $border = '#' unless defined $border;
   my ($corner,$middle) = ('','');
   if (length($border) > 1) {
      $corner = substr($border,0,1);
      $middle = substr($border,2,1);
      $border = substr($border,1,1);
   }#endif
   $center = 1 unless defined $center;
   $msg =~ s/\n$//; # Remove any trailing line ending
   my (@msg) = split("\n",$msg); # Separate the lines out
   # Look for the longest line length
   my ($max) = 0;
   foreach (@msg) {
      $max = length if length > $max;
   }#endforeach
   my ($fl,$fr);
   foreach $msg (@msg) {
      if ($center) {
         $fr = ($max-length($msg))/2;
         $fl = int($fr);
         $fr = ($fr > $fl) ? ($fl+1) : ($fl);
      } else {
         $fl = 0;
         $fr = $max - length($msg);
      }#endif
      $msg = $border.' '.(' ' x $fl).$msg.(' ' x $fr).' '.$border;
   }#endforeach
   $max += 4;
   push(@msg,$border x $max);
   unshift(@msg,$border x $max);
   if ($corner) {
      $msg[0]     =~ s/^.(.*).$/$corner$1$corner/;
      $msg[$#msg] =~ s/^.(.*).$/$corner$1$corner/;
   }#endif
   if ($middle) {
      for (@msg[1..($#msg-1)]) {
         s/^.(.*).$/$middle$1$middle/;
      }#endfor
   }#endif
   join("\n",@msg) . "\n";
}#endsub Box

############################################################################
sub VersionBanner {
   my ($local_vers) = @_;
   $local_vers = $main::vers unless $local_vers;
   my $vers = $main::revn;
   my ($vb_state) = $local_vers;
   if ($0 =~ m/\.(old|test|beta|alpha|exp|(\d+\..+))$/i) {
      $vb_state = " $1 ";
      $vb_state =~ lc($vb_state);
      $vb_state =~ s/\d\.\S+/Specified/;
   }#endif
   $vb_state =~ s/exp|test|Experimental/Exp/;
   $vb_state =~ s/beta/Beta/;
   $vb_state =~ s/alpha/Alpha/;
   $vb_state =~ s/old/Old/;
   my ($banner) = '';
   if ($revn =~ m/released/) {
      $banner = "Production Version - Please report any problems.\n";
   } elsif ($vb_state =~ m/Exp/) {
      $banner = <<'.';
EXPERIMENTAL VERSION
--------------------
EXPECT MANY PROBLEMS
.
   } elsif ($vb_state =~ m/Alpha/) {
      $banner = <<'.';
ALPHA version - EXPECT minor problems
.
   } elsif ($vb_state =~ m/Beta/) {
      $banner = <<'.';
BETA version - possible problems 
.
   } elsif ($vb_state =~ m/Old/) {
      $banner = <<'.';
Old version - possible problems 
.
   } elsif ($vb_state =~ m/Specified/) {
      $banner = <<'.';
Specified version - known characteristics 
.
   } else {
      $banner = "Production Version - Please report any problems.\n";
   }#endif
   &Box($banner."$local_vers\n",'+-|');
}#endsub VersionBanner

#############################################################################
sub Mo {
   my ($mo) = @_;
   my (@mo) = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
   return $mo[$mo];
}#endsub Mo

#############################################################################
sub RcsDate {
   my (@info) = split(' ',$vers);
   my ($mo,$da,$yr);
   $info[3] =~ m:\d\d(\d\d)/(\d\d)/(\d\d):;
   ($mo,$da,$yr) = ($2,$3,$1);
   $mo = &Mo($mo-1);
   ("$da $mo $yr");
}#endsub RcsDate

{
##############################################################################
# Documentation subroutines: Usage, Page, & Manpage
##############################################################################
sub Usage {
   my ($srcfile,$message,@SEARCH) = @_;
   $srcfile = $0 unless $srcfile ne '';
   if (not -r $srcfile and $srcfile !~ m:/:) {
      # Try search path
      my ($dir,$file);
      for $dir (@SEARCH,split(':',$ENV{'PATH'})) {
         $file = (($dir ne '')?($dir.'/'):('')).$srcfile;
         last if -r $file;
      }#endfor
      $srcfile = $file;
      &Die("Usage unable to find $srcfile!?") unless -r $srcfile;
   } else {
      &Die("Usage unable to find $srcfile!?") unless -r $srcfile;
   }#endif
   printf "\n";
   printf "NOTE: %s\n\n",$message if $message ne '';
   open(POD,"pod2text $srcfile|");
   POD->autoflush(1);
   while (<POD>) {
      last if m/^DESCRIPTION$/;
      print;
   }#endwhile
   while (<POD>) {
      last if m/^COPYRIGHT$/;
   }#endwhile
   print;
   printf "%s",$_ while <POD>;
   close(POD);
   exit 1;
}#endsub Usage

##############################################################################
# Redirect STDOUT to the pager.
sub Page {
  my $PAGER = 'more';
  $PAGER = $ENV{'PAGER'} if exists $ENV{'PAGER'} and -x $ENV{'PAGER'};
  open(STDOUT,"|nroff -man|uniq|$PAGER");
}#endsub Page

##############################################################################
sub Manpage {
   # Call this routine with no arguments to display.
   my($srcfile,$manfile,@SEARCH) = @_;
   $srcfile = $0 unless $srcfile ne '';
   if (not -r $srcfile and $srcfile !~ m:/:) {
      # Try search path
      my ($dir,$file);
      for $dir (@SEARCH,split(':',$ENV{'PATH'})) {
         $file = (($dir ne '')?($dir.'/'):('')).$srcfile;
         last if -r $file;
      }#endfor
      $srcfile = $file;
      &Die("Manpage unable to find $srcfile!?") unless -r $srcfile;
   } else {
      &Die("Manpage unable to find $srcfile!?") unless -r $srcfile;
   }#endif
   if ($manfile eq '') {
      &Page;
   } else {
      open(MANFILE,">$manfile");
      MANFILE->autoflush(1);
   }#endif
   $revn = $main::revn;
   $pod2man="pod2man --section=1 --center='EDA script' --release='$revn'";
   open(MANPAGE,"$pod2man $srcfile|");
   if ($manfile eq '') {
      print STDOUT <MANPAGE>;
   } else {
      print MANFILE <MANPAGE>;
   }#endif
   close(MANPAGE);
   if ($manfile eq '') {
      close(STDOUT);
   } else {
      close(MANFILE);
      print STDERR "Extracted manpage file $manfile\n";
   }#endif
}#endsub Manpage
}

#############################################################################
sub numerically { $a <=> $b }

#############################################################################
sub Keep {
# Returns an array containing two file names. First file name is unique
# by renaming any conflicts if possible. Second file name contains new
# name of the old file if any.
#
   my ($file) = @_;
   return ($file,'') unless (-e $file); # already unique
   my ($separator) = '-#';
   my ($directory) = '.';
   my ($num) = 1;
   my (@FILELIST);
   $directory = $file if $file =~ m:/:;
   $directory =~ s:/[^/]*$::;
   $file =~ s:.*/::;
   my ($length) = length($file) + length($separator);
   # Glob the directory
   opendir(DIR,$directory) or &Die("Couldn't open directory $directory\n");
   @FILELIST = readdir(DIR);
   closedir(DIR);
   # Search for older files of this base name
   @FILELIST = grep(/^$file$separator\d+$/,@FILELIST);
   if (@FILELIST == 0) {
      # Assert: no older files of this base name exist
      rename ("$directory/$file","$directory/$file$separator$num") or &Die("Couldn't rename $directory/$file");
      return ("$directory/$file","$directory/$file$separator$num");
   }#endif
   foreach $num (@FILELIST) {
      $num = substr($num,$length);
   }#endforeach
   @FILELIST = sort numerically @FILELIST;
   $num = $FILELIST[$#FILELIST]+1;
   push(@FILELIST,$num);
   rename("$directory/$file","$directory/$file$separator$num") or &Die("Couldn't rename $directory/$file");
   if ($MAX_KEPT >= 0 && scalar(@FILELIST) >= $MAX_KEPT) {
      splice(@FILELIST,-($MAX_KEPT)) if $MAX_KEPT > 0;
      foreach $num (@FILELIST) {
         unlink("$directory/$file$separator$num") or &Die("Couldn't remove $directory/$file$separator$num");
      }#endfor
   }#endif
   return ("$directory/$file","$directory/$file$separator$num");
}#endsub Keep

#############################################################################
sub InsertARGV {
   return unless @_;
   my (@ARGS) = @_;
   my (@GLOB) = ();
   my ($arg);
   foreach $arg (@ARGS) {
      if ($arg =~ m/[*?\[]/) {
         push(@GLOB,split(' ',`echo $arg`));
      } else {
         push(@GLOB,$arg);
      }#endif
   }#endforeach $arg
   unshift(@ARGV,@GLOB);
}#endsub InsertARGV

#############################################################################
sub Eval {
   my ($expr) = @_;
   my $result = eval($expr);
   &Warn($@) if $@;
   &Debug(0x0010,"EVAL '$expr' -> '$result'");
   &Debug(0x0040,"EVAL %VARS = (\n".&Dump_Vars.");");
   return $result;
}#endsub

#############################################################################
sub Process_Command_Line {
   my $arg;
   my (@OPTS);
   @INPUT_FILES = ();
   @OPTS = @ORIG = @ARGV;
   foreach $opt (@OPTS) {
      next unless $opt =~ m/\s/;
      $opt = "'$opt'";
   }#endforeach $opt
   &InsertARGV(split(' ',$ENV{$TOOL})) if defined $ENV{$TOOL};

   ARG: while (@ARGV) { # ARGV LOOP
      $arg = shift(@ARGV);
      #--------------------------------------------------------------------
      if ($arg eq '-?' or $arg eq '--usage') { # synopsis
           &Usage($0);
           exit 0;
      #--------------------------------------------------------------------
      } elsif ($arg eq '-h' or $arg eq '--help') { # help
           &Manpage($0);
           exit 0;
      #--------------------------------------------------------------------
      } elsif ($arg =~ m/^[a-zA-Z]\w+\=\w+$/) { # Environmental variables
           eval "\$ENV{'$1'}=$2";
      #--------------------------------------------------------------------
      } elsif ($arg eq '-c' or $arg eq '--context') { # context
           &Warn("Bad arguments to $arg") unless $ARGV[0] =~ m/(\d+)\.\.(\d+)/;
           &Required_Context($1,$2);
           shift(@ARGV);
      #--------------------------------------------------------------------
      } elsif ($arg eq '--debug') { # dump parsed rules when interrupted
           $debug_dump = 1;
      #--------------------------------------------------------------------
      } elsif ($arg =~ m/^-d\d*/ or $arg eq '--dump') { # dump parsed rules and quit
           $only_rules = 1;
           $only_rules = $& if $arg =~ m/\d+/;
           if ($ARGV[0] =~ /$EXTN$/) {
              $DUMP_FILE = shift(@ARGV);
           }#endif
      #--------------------------------------------------------------------
      } elsif ($arg eq '-e' or $arg eq '--extn') { # extension specification
           &Warn("Missing argument for $arg") unless $ARGV[0];
           $EXTN = shift(@ARGV);
      #--------------------------------------------------------------------
      } elsif ($arg eq '-f') { # required include
           &Warn("Missing argument for $arg") unless $ARGV[0];
           if (-r $ARGV[0]) {
               &Read_Rules;
               &Include(shift(@ARGV));
           } else {
               &Warn("Missing file for $arg");
           }#endif
      #--------------------------------------------------------------------
      } elsif ($arg eq '-F' and $ARGV[0]) { # optional include
           &Warn("Missing argument for $arg") unless $ARGV[0];
           if (-r $ARGV[0]) {
               &Read_Rules;
               &Include(shift(@ARGV));
           }#endif
      #--------------------------------------------------------------------
      } elsif ($arg eq '-keep' or $arg eq '--keep') { # indicate base rules to use
           &Warn("Missing argument to $arg") unless $ARGV[0] =~ m/^-?\d+$/;
           $MAX_KEPT = shift(@ARGV);
      #--------------------------------------------------------------------
      } elsif ($arg eq '-k' or $arg eq '--kind') { # indicate base rules to use
           &Warn("Missing argument to $arg") unless $ARGV[0] =~ m/^\w+$/;
           $KIND = shift(@ARGV);
      #--------------------------------------------------------------------
      } elsif ($arg eq '-l' or $arg eq '--logfile' or $arg eq '-o') { # log file
           &Warn("Missing logfile name in $arg") unless $ARGV[0] =~ m/\S+/;
           &Create_Rpt(shift(@ARGV));
      #--------------------------------------------------------------------
      } elsif ($arg eq '-man') { # output manpage file
           &Manpage($0,"$tool.1");
           exit 0 unless @ARGV;
      #--------------------------------------------------------------------
      } elsif ($arg eq '-n') { # suppress output context
           $message_only = 1;
      #--------------------------------------------------------------------
      } elsif (($arg eq '-p' or $arg eq '--path') and $ARGV[0]) { # search path
           $arg = shift(@ARGV);
           if ($arg =~ s/^[\^]//) {
               unshift(@RULE_PATH, split(':',$arg));
           } elsif ($arg =~ s/^[\$]//) {
               push(@RULE_PATH, split(':',$arg));
           } else {
               @RULE_PATH = split(':',$arg);
           }#endif
      #--------------------------------------------------------------------
      } elsif ($arg eq '-q') { # quiet
           $verbosity = 'quiet';
      #--------------------------------------------------------------------
      } elsif ($arg eq '-INSTALL') { # simple installation
           print STDOUT "Installing...\n" unless &Quiet;
           $found = 0;
           @DATA = <main::DATA> unless defined @DATA;
           for (@DATA) {
               if (/^__INSTALL__$/) {
                   $found = 1;
               } elsif (/^__EOF__$/) {
                   $found = 0;
               } elsif ($found and /^__PERL__\s+/) {
                   chomp($cmd = $');
                   print STDOUT "INSTALL-PERL> ",$cmd;
                   eval($cmd);
               } elsif ($found and /^__EXEC__\s+/) {
                   $cmd = $';
                   $cmd = eval('"'.$cmd.'"');
                   print STDOUT "INSTALL> ",$cmd;
                   $exit = system($cmd)/256;
                   print "Exitcode $exit\n" if $exit;
                   $found = 2;
               } elsif ($found) {
                   chomp;
                   print eval('"'.$_.'\n"');
               }#endif
           }#endwhile
           exit 0;
      #--------------------------------------------------------------------
      } elsif ($arg eq '-XL') { # list files to extract
           @DATA = <main::DATA> unless defined @DATA;
           print STDOUT "Extractable files (-XT):\n";
           for (@DATA) {
               if (! m/^__EOF__$/ and m/^__([^_]\S*)__$/) {
                   $title = $1;
                   next if $title eq 'MANPAGE' or $title eq 'INSTALL';
                   $title = lc($title) if index($title,'.') > 0;
                   print STDOUT "  ",$title,"\n" unless &Quiet;
               }#endif
           }#endfor
           exit 0;
      #--------------------------------------------------------------------
      } elsif ($arg eq '-XT') { # extract various tests UNDOCUMENTED
           &Warn("Missing argument to $arg") unless $ARGV[0] =~ m/\S+/;
           $case = shift(@ARGV);
           $CASE = uc($case);
           $title = "Writing $case\n";
           $found = 0;
           @DATA = <main::DATA> unless defined @DATA;
           for (@DATA) {
               if (/^__${CASE}__$/) {
                   $found = 1;
                   print STDOUT $title unless &Quiet;
                   open(OUT,">$case") or die "Unable to write $case!?\n";
                   OUT->autoflush(1);
               } elsif (/^__EOF__$/) {
                   $found = 0;
               } elsif ($found and /^__PERL__\s+/) {
                   chomp($cmd = $');
                   eval($cmd);
               } elsif ($found and /^__EXEC__\s+/) {
                   $cmd = $';
                   $cmd = eval('"'.$cmd.'"');
                   print STDOUT "$TOOL> ",$cmd if &Verbose;
                   $exit = system($cmd)/256;
                   print "Exitcode $exit\n" if $exit;
               } elsif ($found) {
                   print OUT $_;
                   $found = 2;
               }#endif
           }#endwhile
           close(OUT);
           exit 0 unless $ARGV[0] eq '-XT';
      #--------------------------------------------------------------------
      } elsif ($arg eq '-html') { # run logfile through vim's 2html
           $OPT_html = 1;
      #--------------------------------------------------------------------
      } elsif ($arg eq '-j') { # provide rule number in ouput
           $OPT_justify = 1;
      #--------------------------------------------------------------------
      } elsif (index($arg,'-tee')==0) { # tee
           $tee = 1;
      #--------------------------------------------------------------------
      } elsif ($arg =~ m/^-D(\dx?\d*)/) { # debugging (not documented)
           $DEBUG = $1;
           $DEBUG = hex($DEBUG) if $DEBUG =~ m/x/;
           &Debug($DEBUG,sprintf("debuging level 0x%x",$DEBUG));
           &Printf2Both($banner) unless defined $banner_done;
           $banner_done = 1;
      #--------------------------------------------------------------------
      } elsif (index($arg,'-v')==0) { # verbose
           $verbosity = 'very';
           $DEBUG = $1 if $arg =~ m:^-v(\d+)$:; # debugging (not documented)
           $DEBUG = hex($DEBUG) if $DBUG =~ m/x/;
           &Printf2Both($banner) unless defined $banner_done;
           $banner_done = 1;
      #--------------------------------------------------------------------
      } elsif ($arg eq '-V' or $arg eq '--version') { # display tool version
           printf("%s %s\n",$tool,$revs);
           exit 0 unless @ARGV;
           #&Printf2Log("%s %s\n",$tool,$revs);
      #--------------------------------------------------------------------
      } elsif ($arg =~ m/^-w\d*$/) { # wrap
           $WRAP = 78;
           $WRAP = $& if $arg =~ m/\d+/;
      #--------------------------------------------------------------------
      } elsif ($arg eq '-x') { # explicit rule
           &Warn("Missing argument to $arg") unless $ARGV[0];
           &Read_Rules;
           $RULE_FILE = '';
           $RULE_LNO = '';
           &Parse_Rule(shift(@ARGV));
      #--------------------------------------------------------------------
      } elsif ($arg eq '-banner' or $arg eq '--banner') { # report PASSED/FAILED
           $OPT_banner = 1;
      #--------------------------------------------------------------------
      } elsif ($arg eq '-passfail' or $arg eq '--passfail') { # report PASSED/FAILED
           $OPT_passfail = 1;
      #--------------------------------------------------------------------
      } elsif ($arg eq '-X' or $arg eq '--exact') { # exact matching - no allowances
           $OPT_exact = 1;
      #--------------------------------------------------------------------
      } elsif ($arg ne '' and index($arg,'-') != 0) { # input file
           &Warn("File '$arg' not readable") unless -r $arg;
           push(@INPUT_FILES,$arg);
      #--------------------------------------------------------------------
      } else { # oops...
           &Warn("Unknown command line option");
      }#endif
   }#endwhile
   &Printf2Both($banner) unless defined $banner_done;
   $banner_done = 1;
   #Debug(0x0001,"EXITING Process_Command_Line");
}#endsub Process_Command_Line

#############################################################################
sub Adv_Field {
   my ($value,$mask) = @_;
   my $save = $value & ~ $mask;
   my $lsb = 1;
   $lsb <<= 1 until $lsb & $mask;
   $value = ($value & $mask) + $lsb;
   $value = $mask unless $value & $mask;
   $value = $save | $value;
}#endsub Adv_Field

#############################################################################
sub Exit_Status {
   my $Exit_Status = 0;
   my $log2;
   $Exit_Status = 128 if $STAT{'fatal'} > 0;
   if ($STAT{'severe'} > 0) {
      $log2 = int(log($STAT{'severe'}) / log(2)) + 1;
      $log2 = 7 if $log2 > 7;
      $Exit_Status |= ($log2 << 4);
   }#endif
   if ($STAT{'error'} > 0) {
      $log2 = int(log($STAT{'error'}) / log(2)) + 1;
      $log2 = 15 if $log2 > 15;
      $Exit_Status |= $log2;
   }#endif
   return $Exit_Status
}#endsub Exit_Status

#############################################################################
sub Sanity {
   return if &Quiet or (time - $sane) < 15;
   $crazy++;
   print $oops ? '!' : $yea ? ':' : '.';
   $yea =  0;
   $oops = 0;
   $sane = time;
   return if $crazy < 70;
   print "\n";
   $crazy = 0;
}#endsub Sanity

#############################################################################
sub Next_Log_Line {
   return 0 if eof INPUT_HNDL and @SHOWN == 0;
   my $line;
   if (@SHOWN) {
      $line = shift(@SHOWN);
      $INPUT_LNO++;
   } else {
      &Sanity;
      chomp($line = <INPUT_HNDL>);
      $INPUT_LNO = $.;
   }#endif
   $linecount++;
   $INPUT_TXT = $line;
   #Debug(0x0002,"INPUT: $INPUT_TXT");
   push(@CONTEXT_BUF,$INPUT_TXT);
   return 1;
}#end Next_Log_Line

#############################################################################
sub Next_Sho_Line {
   return 0 if eof INPUT_HNDL and @SHOWN == 0;
   my $line;
   if (@SHOWN) {
      $line = shift(@SHOWN);
   } else {
      &Sanity;
      chomp($line = <INPUT_HNDL>);
   }#endif
   $INPUT_TXT = $line;
   push(@SHOWN,$line);
   return 1;
}#end Next_Sho_Line

#############################################################################
#
#  ######                                                  
#  #     #  #####    ####    ####   ######   ####    ####  
#  #     #  #    #  #    #  #    #  #       #       #      
#  ######   #    #  #    #  #       #####    ####    ####  
#  #        #####   #    #  #       #            #       # 
#  #        #   #   #    #  #    #  #       #    #  #    # 
#  #        #    #   ####    ####   ######   ####    ####  
#
#############################################################################
sub Process_Log_Files {
   my (
      $ena, # true, false
      $tag, # <IDENT>
      $typ, # @TYP
      $cnd, # {if, unless, expect, never}
      $cmp, # {equals, contains, firstword, matches}
      $pat, # <PATTERN>
      $mul, # 0, <COUNT>
      $ctx, # <IDENT> context to m
      $cty, # <IDENT> new context
      $inc, # <FILE>
      $act, # {enable, disable}
      $ds0, # <IDENT>
      $dst, # <IDENT>
      $msg, # "found $&"
      $cnt, # 0..
      $min, # '', <COUNT>
      $max, # '', <COUNT>
      $sho, # 0, <COUNT>
      $frc, # false, true
      $and, # '', expr
      $alw, # '', expr
      $pre, # '', expr
      $evl, # '', expr
   );
   $SIG{'INT'} = \&Handler2;
   local $linecount = 0;
   &Save_Rules;
   MAIN: foreach $INPUT_FILE (@INPUT_FILES) {
      $CONTEXT_TAG = '';
      $CONTEXT_TXT = '';
      $CONTEXT_LNO = 0;
      @CONTEXT_BUF = ();
      &Restore_Rules;
      open(INPUT_HNDL,"<$INPUT_FILE") or &Die("Unable to open $INPUT_FILE for reading.");
      &Printf2Both("\n") if $crazy;
      $crazy = 0;
      &Printf2Both("%s\n",($sep0 x $SW)); # separator
      &Printf2Both("INFO: Processing $INPUT_FILE\n\n");
      $start = time();
      LINE: while (&Next_Log_Line) {
         last LINE if $request eq 'INT';
         #----------------------------------------------------------------
         # get rid of excess context
         #----------------------------------------------------------------
         shift(@CONTEXT_BUF) if scalar(@CONTEXT_BUF) > $required_context;
         #----------------------------------------------------------------
         # check against the rules in reverse order to allow overrides
         #----------------------------------------------------------------
         $skip = $FALSE;
         RULE: for ($iRULE=$#RULE_LOL; $iRULE >= $[; $iRULE--) {
            $RULE = $RULE_LOL[$iRULE];
            $typ = $RULE->[$fTYP];
            #Debug(0x0002,"EVALUATING rule $typ");

            $cnd = $RULE->[$fCND];
            $cmp = $RULE->[$fCMP];
            next RULE if $cnd eq 'post' or $cmp eq 'expr'; # handled after file scan

            #------------------------------------------------------------
            # is this rule enabled?
            #------------------------------------------------------------
            $ena = $RULE->[$fENA];
            next RULE unless $ena;
            $frc = $RULE->[$fFRC];
            next RULE if $skip and (!$frc or $typ =~ m/^(count|eval|alert|info|context|require|include|use)$/);

            #------------------------------------------------------------
            # evaluate context conditioning
            #------------------------------------------------------------
            $ctx = $RULE->[$fCTX];
            if ($ctx ne '') {
               next RULE unless $CONTEXT_TAG =~ m/$ctx/;
            }#endif

            #------------------------------------------------------------
            # Evaluate pattern conditioning
            #------------------------------------------------------------
            PATTERN: {
            $found = $FALSE; # assumption
            $pat = $RULE->[$fPAT];
            $mul = $RULE->[$fMUL];
            if ($mul) { # multi-line match!
               #Debug(0x0002,"MATCHING multiple lines");
               #--------------------------------------------------------
               # Grab the lines and concatenate
               #--------------------------------------------------------
               $mul = $#CONTEXT_BUF - $mul;
               $mul = 0 if $mul < 0;
               $the_text = join("\n",@CONTEXT_BUF[$mul..$#CONTEXT_BUF]);
            } else {
               $the_text = $CONTEXT_BUF[$#CONTEXT_BUF];
            }#endif

            #------------------------------------------------------------
            # Pre-process if requested
            #------------------------------------------------------------
            $pre = $RULE->[$fPRE];
            if ($pre ne '') {
               $_ = $the_text;
               &Eval($pre);
               $the_text = $_;
            }#endif

            #------------------------------------------------------------
            # Perform the comparison
            #------------------------------------------------------------
            $and = '';
            @FOUND = (('') x 8);
            if      ($cmp eq 'equals') {
               $found = ($the_text eq $pat);
               @FOUND = (($pat) x 8) if $found;
            } elsif ($cmp eq 'contains') {
               $found = index($the_text, $pat) >= 0;
               @FOUND = (($pat) x 8) if $found;
            } elsif ($cmp eq 'firstword') {
               ($first_text = $the_text) =~ s/^\s+//;
               $found = (index($first_text,$pat) == 0 and
                         index($WS,substr($first_text,length($pat),1)) >= 0);
               @FOUND = (($pat) x 8) if $found;
            } elsif ($cmp eq 'words') {
               $found = ($the_text =~ m/\b$pat\b/m);
               @FOUND = ($&,$+,$1,$2,$3,$4,$5,$6) if $found;
            } elsif ($cmp eq 'matches') {
               $found = ($the_text =~ m/$pat/m);
               @FOUND = ($&,$+,$1,$2,$3,$4,$5,$6) if $found;
            } else {
               $RULE_FILE = $RULE->[$fFIL];
               $RULE_LNO = $RULE->[$fLIN];
               $INTERNAL = $TRUE;
               &Warn("Illegal comparison in rule");
            }#endif
            next RULE unless $found;
            }#end PATTERN

            #------------------------------------------------------------
            # Consider 'and' clause if needed
            #------------------------------------------------------------
            if ($and eq '') {
               $and = $RULE->[$fAND]; # additional clause?
               next if $and ne '' and not &Eval($and);
            }#endif

            $alw = $RULE->[$fALW];
            $min = $RULE->[$fMIN];
            $max = $RULE->[$fMAX];
            my $variance = 0;
            if (($max eq '' or  ($cnt + 1) < $max) and $alw ne '') {
               $variance = not &Eval($alw);
               $allowed = 0 if $allowed eq ''; 
               $allowed++ if $variance;
            }#endif
            next LINE if $variance and $OPT_exact;

            #------------------------------------------------------------
            # Pattern matches so count it!
            #------------------------------------------------------------
            $yea++;
            $cnt = $RULE->[$fCNT] + 1; # every match must be counted
            $RULE->[$fCNT] = $cnt;

            #------------------------------------------------------------
            # Handle immediate evaluations
            #------------------------------------------------------------
            if (($cnd eq 'if'     and ($min eq '' or $min <= $cnt)) and ($max eq '' or $cnt <= $max) 
            or  ($cnd eq 'unless' and ($min  eq ''or $min <= $cnt))
            ) {
               $evl = $RULE->[$fEVL];
               &Eval($evl) if $evl ne '';
               $cty = $RULE->[$fCTY];
               if ($cty ne '') {# load context register
                  $CONTEXT_TAG = $cty;
                  $CONTEXT_TXT = $INPUT_TXT;
                  $CONTEXT_LNO = $INPUT_LNO;
               }#endif
            }#endif

            #------------------------------------------------------------
            # consider min/max requirements
            #------------------------------------------------------------
            if (   ($cnd eq 'unless' and ($max eq '' or $cnt <= $max))
               or ($min ne '' and $cnt < $min)
               or ($cnd eq 'if' and $max ne '' and $cnt > $max)
            ) {
               $skip = $TRUE;
               next RULE;
            }#endif

            #------------------------------------------------------------
            # Pattern matched pattern, clause and count!
            #------------------------------------------------------------

            #------------------------------------------------------------
            # Complete match found!
            #------------------------------------------------------------
            $msg = $RULE->[$fMSG];
            $sho = $RULE->[$fSHO];
            $tag = $RULE->[$fTAG];
            $STAT{$INPUT_FILE,$typ}++; # local count
            $STAT{$typ}++;             # global count

            #------------------------------------------------------------
            # Execute enable/disable
            #------------------------------------------------------------
            $act = $RULE->[$fACT];
            if ($act eq 'enable' or $act eq 'disable') {
               $dst = $RULE->[$fDST];
               &Enable_Rule($dst,$act eq 'enable');
               &Info($iRULE,$tag,$typ,$cnd,$msg,$ctx,$sho,$INPUT_FILE,$INPUT_LNO,$cmp,$pat,$cnt,$min,$max,@FOUND) if $msg ne '';
            } elsif ($act ne '') {
               $RULE_FILE = $RULE->[$fFIL];
               $RULE_LNO = $RULE->[$fLIN];
               &Warn("Unknown action '$act'");
            }#endif

            #------------------------------------------------------------
            # Execute actions
            #------------------------------------------------------------
            ACTION: {
            if      ($typ eq 'fatal'  ) {# 128    message & exit program
               #### fatal   128     message & exit program
               $oops++;
               &Message($iRULE,$tag,$typ,$cnd,$msg,$ctx,$sho,$INPUT_FILE,$INPUT_LNO,$cmp,$pat,$cnt,$min,$max,@FOUND);
               last LINE;
            } elsif ($typ eq 'severe' ) {# 64-127 message & next line
               #### severe  64..127 message & next line
               $oops++;
               &Message($iRULE,$tag,$typ,$cnd,$msg,$ctx,$sho,$INPUT_FILE,$INPUT_LNO,$cmp,$pat,$cnt,$min,$max,@FOUND);
               $skip = $TRUE;
               next RULE;
            } elsif ($typ eq 'error'  ) {# 1-63   message & next line
               #### error   1..63   message & next line
               $oops++;
               &Message($iRULE,$tag,$typ,$cnd,$msg,$ctx,$sho,$INPUT_FILE,$INPUT_LNO,$cmp,$pat,$cnt,$min,$max,@FOUND);
               $skip = $TRUE;
               next RULE;
            } elsif ($typ eq 'warning') {# 0      message & next line
               #### warning 0       message & next line
               $oops++;
               &Message($iRULE,$tag,$typ,$cnd,$msg,$ctx,$sho,$INPUT_FILE,$INPUT_LNO,$cmp,$pat,$cnt,$min,$max,@FOUND);
               $skip = $TRUE;
               next RULE;
            } elsif ($typ eq 'alert'  ) {# 0      message (type of warning)
               #### alert   0       message (considered a warning)
               $oops++;
               &Message($iRULE,$tag,$typ,$cnd,$msg,$ctx,$sho,$INPUT_FILE,$INPUT_LNO,$cmp,$pat,$cnt,$min,$max,@FOUND);
            } elsif ($typ eq 'note'   ) {# 0      message & next line
               #### note    0       message & next line
               &Message($iRULE,$tag,$typ,$cnd,$msg,$ctx,$sho,$INPUT_FILE,$INPUT_LNO,$cmp,$pat,$cnt,$min,$max,@FOUND);
               $skip = $TRUE;
               next RULE;
            } elsif ($typ eq 'info'   ) {# 0      message (type of note)
               #### info    0       message (considered a note)
               &Message($iRULE,$tag,$typ,$cnd,$msg,$ctx,$sho,$INPUT_FILE,$INPUT_LNO,$cmp,$pat,$cnt,$min,$max,@FOUND);
            } elsif ($typ eq 'eval'  ) {# 0      count
               # already done
            } elsif ($typ eq 'count'  ) {# 0      count
               #### count   0       count
               # already done
            } elsif ($typ eq 'ignore' ) {# 0      next line
               #### ignore  0       next line
               $skip = $TRUE;
               next RULE;
            } elsif ($typ eq 'context') {# -      load context register
               #### context -       load context register
               $CONTEXT_TAG = $tag;
               $CONTEXT_TXT = $INPUT_TXT;
               $CONTEXT_LNO = $INPUT_LNO;
            } elsif ($typ eq 'require') {# -      append rules
               #### require -       append rules
               $inc = $RULE->[$fINC];
               my $path = &Find_File($inc);
               if ($path ne '') {
                  &Include($path);
               } else {
                  &Warn("Missing file '$inc' for $typ");
               }#endif
            } elsif ($typ eq 'include') {# -      append rules if found
               #### include -       append rules if found
               $inc = $RULE->[$fINC];
               my $path = &Find_File($inc);
               if ($path ne '') {
                  &Include($path);
               }#endif
            } elsif ($typ eq 'enable' or $typ eq 'disable') {
               $ds0 = $RULE->[$fDS0];
               &Enable_Rule($ds0,$typ eq 'enable');
               &Info($iRULE,$tag,$typ,$cnd,$msg,$ctx,$sho,$INPUT_FILE,$INPUT_LNO,$cmp,$pat,$cnt,$min,$max,@FOUND) if $msg ne '';
            } elsif ($typ eq 'use'    ) {# -      read new set of rules
               #### use     -       read new set of rules
               $inc = $RULE->[$fINC];
               my $path = &Find_File($inc);
               if ($path ne '') {
                  &Reset_Rules; # start fresh
                  &Include($path);
               } else {
                  &Warn("Missing file '$inc' for $typ");
               }#endif
            } else {
               &Warn("Illegal type $typ");
            }#endif
            }#end ACTION
         }#endforeach $RULE

      }#endwhile <INPUT_HNDL>
      close(INPUT_HNDL);
      &Printf2Both("\n") if $crazy;
      $crazy = 0;

      #================================================================
      # Check requirements (unless counts) and post processing rules
      #----------------------------------------------------------------
      &Debug(0x0001,"POST Checking requirements and post processing rules");
      REQD: for ($iRULE=$#RULE_LOL; $iRULE >= $[; $iRULE--) {
         $RULE = $RULE_LOL[$iRULE];
         $cnd = $RULE->[$fCND];
         $cmp = $RULE->[$fCMP];
         $typ = $RULE->[$fTYP];
         $ena = $RULE->[$fENA];
         $cnt = $RULE->[$fCNT];
         $min = $RULE->[$fMIN];
         $max = $RULE->[$fMAX];
         next REQD unless $ena;
         #------------------------------------------------------------
         # Context, patterns, and pre-processing
         # are meaningless at this point
         #------------------------------------------------------------
         if ($cmp eq 'expr') {
            #---------------------------------------------------------
            # Process 'eval' BEFORE checking condition
            #---------------------------------------------------------
            $evl = $RULE->[$fEVL];
            &Eval($evl) if $evl ne '';
            #---------------------------------------------------------
            # Now see if we need to emit a message
            #---------------------------------------------------------
            $and = $RULE->[$fAND];
            if ($and ne '' and not &Eval($and)) {
               $msg = $RULE->[$fMSG];
               $ctx = $RULE->[$fCTX];
               $pat = $RULE->[$fPAT];
               $tag = $RULE->[$fTAG];
               $STAT{$INPUT_FILE,$typ}++; # local count
               $STAT{$typ}++;             # global count
               @FOUND = ();
               &Message($iRULE,$tag,$typ,$cnd,$msg,'',$sho,$INPUT_FILE,'',$cmp,$pat,$cnt,$min,$max,'');
               next REQD;
            }#endif
            #---------------------------------------------------------
            # Was there an "allowed" condition?
            #---------------------------------------------------------
            $alw = $RULE->[$fALW];
            if ($alw ne '') {
               $allowed = 0 if $allowed eq ''; 
               if (not &Eval($alw)) {
                  # Not exactly the same, thus variance
                  $allowed++;
                  #---------------------------------------------------
                  # If user specified -exact, then issue message
                  #---------------------------------------------------
                  if ($OPT_exact) {
                     $msg = $RULE->[$fMSG];
                     $ctx = $RULE->[$fCTX];
                     $pat = $RULE->[$fPAT];
                     $tag = $RULE->[$fTAG];
                     $STAT{$INPUT_FILE,$typ}++; # local count
                     $STAT{$typ}++;             # global count
                     @FOUND = ();
                     &Message($iRULE,$tag,$typ,$cnd,$msg,'',$sho,$INPUT_FILE,'',$cmp,$pat,$cnt,$min,$max,'');
                     next REQD;
                  }#endif
               }#endif
            }#endif
            next REQD;
         } elsif ($cnd eq 'post') {
            #---------------------------------------------------------
            # Process 'eval' BEFORE messages
            #---------------------------------------------------------
            $evl = $RULE->[$fEVL];
            &Eval($evl) if $evl ne '';
            next REQD if $typ eq 'eval';
            #---------------------------------------------------------
            # Issue messages
            #---------------------------------------------------------
            $msg = $RULE->[$fMSG];
            $ctx = $RULE->[$fCTX];
            $pat = $RULE->[$fPAT];
            $tag = $RULE->[$fTAG];
            $STAT{$INPUT_FILE,$typ}++; # local count
            $STAT{$typ}++;             # global count
            @FOUND = ();
            &Message($iRULE,$tag,$typ,$cnd,$msg,'',$sho,$INPUT_FILE,'',$cmp,$pat,$cnt,$min,$max,'');
            next REQD;
         } elsif ($typ eq 'count' && $cnt > 0) {
            #---------------------------------------------------------
            # Note final count
            #---------------------------------------------------------
            $msg = $RULE->[$fMSG];
            $ctx = $RULE->[$fCTX];
            $pat = $RULE->[$fPAT];
            $tag = $RULE->[$fTAG];
            $STAT{$INPUT_FILE,$typ}++; # local count
            $STAT{$typ}++;             # global count
            @FOUND = ();
            &Message($iRULE,$tag,$typ,$cnd,$msg,'',$sho,$INPUT_FILE,'',$cmp,$pat,$cnt,$min,$max,'');
            next REQD;
         }#endif
         next unless $cnd eq 'unless';
         #------------------------------------------------------------
         # consider min/max requirements
         #------------------------------------------------------------
###!?       #$min = $max = 1 if $min eq 0 and $max eq 0;
         if (($min ne '' and $cnt < $min) 
         or  ($and ne '' and not &Eval($and))
         #   took care of max during main loop
         ) { # out of range
            $msg = $RULE->[$fMSG];
            $ctx = $RULE->[$fCTX];
            $pat = $RULE->[$fPAT];
            $tag = $RULE->[$fTAG];
            $STAT{$INPUT_FILE,$typ}++; # local count
            $STAT{$typ}++;             # global count
            @FOUND = ();
            &Message($iRULE,$tag,$typ,$cnd,$msg,'',$sho,$INPUT_FILE,'',$cmp,$pat,$cnt,$min,$max,'');
         }#endif
         #------------------------------------------------------------
      }#endforeach $RULE
      if (not $OPT_exact) {
         &Printf2Both("Found %s\n",$allowed,"allowance") if $allowed ne '';
         $STAT{$INPUT_FILE,'allowance'} = $allowed;
         $allowed = '';
      }#endif
        
      #================================================================
      # Output file summary if more than one file
      #----------------------------------------------------------------
      if (@INPUT_FILES > 1) {
         foreach $typ (@STAT) {
            #next unless defined $STAT{$INPUT_FILE,$typ};
            &Printf2Both("Found %s in %s\n",&Plural($STAT{$INPUT_FILE,$typ},$typ,-2,'',1),$INPUT_FILE);
         }#endforeach $typ
      }#endif

   }#endforeach MAIN input_file
   &Printf2Both("%s\n",($sep0 x $SW)); # separator
   &Printf2Both("INFO: Processed %d lines in %s\n",$linecount,&Format_Time(time()-$start));
   $SIG{'INT'} = \&Handler;
}#endsub Process_Log_Files

#############################################################################
sub Format_Time {
   my ($time) = @_;
   my $hr  = int($time / 3600);
   my $minute = int($time / 60) - 60 * $hr;
   my $sec = $time % 60;
   if ($time > 3600) {
      return sprintf("%d hours %02d minutes %02d seconds",$hr,$minute,$sec);
   } elsif ($time > 60) {
      return sprintf("%d minutes %02d seconds",$minute,$sec);
   } elsif ($time == 0) {
      return sprintf("less than 1 second",$sec);
   } else {
      return sprintf("%d seconds",$sec);
   }#endif
}#endsub Format_Time

#############################################################################
sub Reset_Rules {
   @RULE_LOL = %TAG = %TYP = (); # start fresh
}#endsub Reset_Rules

sub Save_Rules {
   my ($i, $j);
   @SAVE_LOL = ();
   for $i (0..$#RULE_LOL) {
      for $j (0..$#{$RULE_LOL[$i]}) {
         $SAVE_LOL[$i][$j] = $RULE_LOL[$i][$j];
      }#endfor $j
   }#endfor $i
}#endsub Save_Rules 

sub Restore_Rules {
   my ($i, $j);
   for $i (0..$#RULE_LOL) {
      for $j (0..$#{$RULE_LOL[$i]}) {
         $RULE_LOL[$i][$j] = $SAVE_LOL[$i][$j];
      }#endfor $j
   }#endfor $i
}#endsub Restore_Rules 

##############################################################################
sub Initialize {
   #----------------------------------------------------------------------------
   # Fields
   #----------------------------------------------------------------------------
   @FLD = (
      'ena', # true, false
      'tag', # <IDENT>
      'typ', # @TYP
      'cnd', # {if, unless}
      'cmp', # {equals, contains, firstword, words, matches}
      'pat', # <PATTERN>
      'mul', # 0, <COUNT>
      'ctx', # <IDENT> context to m
      'cty', # <IDENT> new context
      'inc', # <FILE>
      'act', # {enable, disable}
      'ds0', # <IDENT>
      'dst', # <IDENT>
      'msg', # "found $f&"
      'cnt', # 0..
      'min', # 0, <COUNT>
      'max', # 0, <COUNT>
      'sho', # 0, <COUNT>
      'frc', # false, true
      'and',
      'alw', # time string
      'pre', # time string
      'evl', # time string
      'fil',
      'lin',
   );
   my $i;
   for $i (0..$#FLD) {
      eval ('$f'.uc($FLD[$i]).'='.$i);
   }#endfor

   #----------------------------------------------------------------------------
   # Constants
   #----------------------------------------------------------------------------
   $TRUE  = 1;
   $FALSE = 0;
   $true  = 'true'; # Temporary
   $false = '';     # Temporary
    
   #----------------------------------------------------------------------------
   # Arrays
   #----------------------------------------------------------------------------
   %ALIAS = (
      'warn' => 'warning',
      'fail' => 'fatal',
      'illegal' => 'severe',
      'print' => 'echo',
      'printf' => 'echo',
      'lock' => 'disallow',
      'reset' => 'clear',
      'aka' => 'alias',
      'word' => 'words',
      'firstwords' => 'firstword',
      'exactly' => 'equals',
      'precisely' => 'equals',
      '==' => 'equals',
      '=?' => 'contains',
      '=~' => 'matches',
      '='  => 'equals',
      '?'  => 'contains',
      '~'  => 'matches',
      'incl' => 'include',
      'message' => 'msg',
      'mesg' => 'msg',
      'display' => 'show',
      'force' => 'always',
      'expect' => 'unless',
   );
   @TYP = qw(
      DEBUG
      alert
      context
      count
      error
      eval
      enable
      disable
      fatal
      ignore
      include
      info
      note
      quiet
      require
      severe
      show
      undefined
      use
      verbose
      warning
   );
   @ENA = qw(
      enable
      disable
      clear
   );
   @INC = qw(
      include
      require
      use
   );
   @STAT = qw(
      fatal
      severe
      error
      warning
      count
   );
   @CMP = qw(
      undefined
      equals
      contains
      firstword
      words
      matches
      expr
   );
   @CND = qw(
      if
      unless
      always
      post
      never
   );
   @DIS = qw(
      DEBUG
      alert
      alias
      clear
      context
      count
      disable
      disallow
      enable
      error
      fatal
      ignore
      include
      info
      limit
      note
      quiet
      require
      severe
      use
      verbose
      warning
   );
   @ACT = qw(
      context
      disable
      enable
      eval
      include
      max
      min
      allow
      and
      only
      msg
      show
      always
      require
      use
   );
   %rh = (
      '"'  => '"',
      "'"  => "'",
      "/"  => "/",
      "#"  => "#",
      '{'  => '}',
      '('  => ')',
      '['  => ']',
      '<'  => '>',
      '{=' => '=}',
      '{:' => ':}',
      '{#' => '#}',
   );
   $required_context = 1;
   $SW = 70;
   $sep0 = '=';
   $sep1 = '~';
   $sep2 = '-';
   #------------------------------------------------------------------------
   # Defaults (for those items that can be overridden)
   #------------------------------------------------------------------------
   $verbosity = 'normal';
   &Required_Context(3,2);
   $WRAP = 0;
   $KIND = 'default';
   $EXTN = '.rules';
   $HOME = $ENV{'HOME'} || $ENV{'LOGDIR'} || (getpwuid($<))[7];
   $MAX_KEPT = 1;
   $WS = "\t\n ";
   @RULE_PATH = (
      '$0/../etc',
      '.',
   );
   $SIG{'INT'} = \&Handler;
   $SIG{'KILL'} = \&Handler;
   $DUMP_FILE = $tool.$EXTN;
   &Reset_Rules;
}#endsub Initialize

#############################################################################
sub Required_Context {
   my ($min,$max) = @_;
   if ($min > $max) {
      ($min_context,$max_context) = ($max,$min);
   } else {
      ($min_context,$max_context) = ($min,$max);
   }#endif
   $required_context = $max_context if $required_context < $max_context;
}#endsub Required_Context
    
#############################################################################
sub Eof {
   return $TRUE if $RULE_FILE eq '' or eof(INCL_HNDL);
}#endsub Eof

#############################################################################
sub Next_Rule_Line {
   my ($LNO) = @_;
   my $curr_line = "\\";
   while (substr($curr_line,-1,1) eq "\\") {
      chop($curr_line); # Remove backslash from end of line
      if ($RULE_FILE eq '') {
         &Warn("Missing end of pattern");
      } else {
         chomp($curr_line .= <INCL_HNDL>);
         $LNO = $.;
      }#endif
   }#endwhile
   return ($curr_line,$LNO);
}#endsub Next_Rule_Line

#############################################################################
sub Display_Rule {
   my ($LEVEL,$RULE) = @_;
   my $str = '';
   my $iFLD;
   for $iFLD (0..$#FLD) {
      $str .= sprintf("  %s = '%s'\n", $FLD[$iFLD], $RULE->[$iFLD]);
   }#endfor
   &Debug($LEVEL,"DISPLAY RULE %s",$str);
}#endsub Display_Rule

#############################################################################
sub Show_Rule {
   my ($iRULE) = @_;
   #                      i TYP CNDCMP PAT        CTX MIN    MAX
   return sprintf("Rule #%d: %s %s %s {%s} context(%s) %s<%s<%s",
                  $iRULE,
                  $RULE_LOL[$iRULE]->[$fTYP],
                  $RULE_LOL[$iRULE]->[$fCND],
                  $RULE_LOL[$iRULE]->[$fCMP],
                  $RULE_LOL[$iRULE]->[$fPAT],
                  $RULE_LOL[$iRULE]->[$fCTX],
                  $RULE_LOL[$iRULE]->[$fMIN],
                  $RULE_LOL[$iRULE]->[$fCNT],
                  $RULE_LOL[$iRULE]->[$fMAX],
                 );
}#endsub Show_Rule

#############################################################################
sub Dump_Rules {
   my ($DUMP_FILE,$how) = @_;
   $DUMP_FILE = $tool.$EXTN unless length($DUMP_FILE) > 0;
   open(DUMP,">$DUMP_FILE") or die "Couldn't open $DUMP_FILE!?\n";
   DUMP->autoflush(1);
   printf DUMP "%s\n",q/eval 'exec perl -S $0 ${1+"$@"}'/;
   printf DUMP "%s\n",q/ if $running_under_some_shell;/;
   printf DUMP "\n";
   printf DUMP "require v5.6.1;\n";
   printf DUMP "\n";
   printf DUMP "#%s\n",'-' x $SW;
   printf DUMP "# Tool: %s version %s\n",$TOOL,$revs;
   printf DUMP "# Date: %s\n",$when;
   printf DUMP "# %% telnet -l %s %s\n",$user,$host;
   printf DUMP "# %% cd %s\n",$wd;
   printf DUMP "# %% %s %s\n",$tool,join(' ',@ORIG);
   printf DUMP "#%s\n",'-' x $SW;
   $reqd = $revs unless $reqd;
   printf DUMP "&Die(\"Wrong version compiled rules\") if \$revs < %1.2f;\n",$reqd;
   printf DUMP "\n" if @ECHO;
   foreach (@ECHO) {
      printf DUMP "  &Printf2Log(%s,'%s');\n",'"%s\n"',$_;
   }#endforeach
   printf DUMP "\n" if @ECHO;
   printf DUMP "#   [%s]\n",join(',',@FLD);
   printf DUMP "\n  %s\n",'push @RULE_LOL, (';
   my ($VALUE, $iFLD, $FIELD);
   foreach $RULE (@RULE_LOL) {
      if ($how == 2) {
           printf DUMP "    [\n",;
      }#endif
      $VALUE = '';
      foreach $iFLD (0..$#FLD) {
         $FIELD = $RULE->[$iFLD];
         if ($FIELD =~ /^\d+$/) {
            $VALUE .= $FIELD.', ';
         } else {
            # Handle some escapes first
            $FIELD =~ s:\n:\\n:g;
            # Pass out a quoted string
            if ($FIELD !~ m/'/ and length($FIELD) < 10) {
                   $VALUE .= "'".$FIELD."', ";
            } elsif ($FIELD !~ m/[{}]/) {
                   $VALUE .= "q{".$FIELD."}, ";
            } elsif ($FIELD !~ m#/#) {
                   $VALUE .= "q/".$FIELD."/, ";
            } else {
                   $FIELD =~ s:':\\':g;
                   $VALUE .= "'".$FIELD."', ";
            }#endif
         }#endif
         if ($how == 2) {
               printf DUMP "       %s # %s\n", $VALUE, $FLD[$iFLD];
               $VALUE = '';
         }#endif
      }#endforeach $FIELD
      if ($how == 2) {
           printf DUMP "    ],\n",;
      } else {
           substr($VALUE,-2,2) = '';
           printf DUMP "    [%s],\n",$VALUE;
      }#endif
   }#endforeach $RULE
   printf DUMP "  );\n";
   my ($VAR);
   foreach $VAR (sort keys %main::VAR) {
      printf DUMP "  \$main::VAR{'%s'} = '%s';\n",$VAR, $main::VAR{$VAR};
   }#endforeach
   printf DUMP "  1;\n\n#%-${SW}.${SW}s\n",'-- The end '.('-' x $SW);
   close(DUMP);
   &Printf2Both("Dumped compiled rules to $DUMP_FILE\n");
}#endsub Dump_Rules

sub Dump_Vars {
   my ($VAR,$LST);
   foreach $VAR (sort keys %main::VAR) {
      $LST .= sprintf("  %s => '%s',\n",$VAR, $main::VAR{$VAR});
   }#endforeach
   return $LST;
}#endsub Dump_Vars

#############################################################################
# Similar to index($str,$substr) only works on arrays
sub Index {
   my (@ARR)=@_;
   my $name = pop(@ARR);
   my $index;
   for ($index = 0; $index <= $#ARR; $index++) {
      return $index if $name eq $ARR[$index];
   }#endfor
   return -1;
}#endsub Index

##############################################################################
sub New_Rule {
   my (
      $ena, # true, false
      $tag, # <IDENT>
      $typ, # @TYP
      $cnd, # {if, unless, post, always, never}
      $cmp, # {equals, contains, firstword, words, matches}
      $pat, # <PATTERN>
      $mul, # 0, <COUNT>
      $ctx, # <IDENT> context to m
      $cty, # <IDENT> new context
      $inc, # <FILE>
      $act, # {enable, disable}
      $ds0, # <IDENT>
      $dst, # <IDENT>
      $msg, # "found $&"
      $cnt, # 0..
      $min, # '', <COUNT>
      $max, # '', <COUNT>
      $sho, # 0, <COUNT>
      $frc, # false, true
      $and, # '', expr
      $alw, # '', expr
      $pre, # '', expr
      $evl, # '', expr
   )=@_;
   #Debug(0x0004,"NEW RULE");
   my (@THIS_RULE) = ();
   $THIS_RULE[$fENA] = ($ena ne '')            ? $ena : $TRUE;
   $THIS_RULE[$fTAG] = ($tag ne '')            ? $tag : $RULE_FILE.'//'.$RULE_LNO;
   $THIS_RULE[$fTYP] = (grep($typ eq $_,@TYP)) ? $typ : 'undefined';
   $THIS_RULE[$fCND] = (grep($cnd eq $_,@CND)) ? $cnd : 'never';
   $THIS_RULE[$fCMP] = (grep($cmp eq $_,@CMP)) ? $cmp : 'undefined';
   $THIS_RULE[$fPAT] = ($pat ne '')            ? $pat : "\000";
   $THIS_RULE[$fMUL] = ($mul > 0)              ? $mul : 0;
   $THIS_RULE[$fMSG] = ($msg ne '')            ? $msg : $typ eq 'eval' ? 'Eval in $tag' : 'Found $&';
   $THIS_RULE[$fCTX] = ($ctx ne '')            ? $ctx : '';
   $THIS_RULE[$fCTY] = ($cty ne '')            ? $cty : '';
   $THIS_RULE[$fINC] = ($inc ne '')            ? $inc : '';
   $THIS_RULE[$fACT] = ($act ne '')            ? $act : '';
   $THIS_RULE[$fDS0] = ($ds0 ne '')            ? $ds0 : '';
   $THIS_RULE[$fDST] = ($dst ne '')            ? $dst : '';
   $THIS_RULE[$fCNT] =                                  0;
   $THIS_RULE[$fMIN] = ($min ne '')            ? $min : '';
   $THIS_RULE[$fMAX] = ($max ne '')            ? $max : '';
   $THIS_RULE[$fSHO] = ($sho > 0)              ? $sho : 0;
   $THIS_RULE[$fFRC] = ($frc ne '')            ? $frc : $FALSE;
   $THIS_RULE[$fAND] = ($and ne '')            ? $and : '';
   $THIS_RULE[$fALW] = ($alw ne '')            ? $alw : '';
   $THIS_RULE[$fPRE] = ($pre ne '')            ? $pre : '';
   $THIS_RULE[$fEVL] = ($evl ne '')            ? $evl : '';
   $THIS_RULE[$fFIL] = $RULE_FILE;
   $THIS_RULE[$fLIN] = $RULE_LNO;
   return @THIS_RULE;
}#endsub New_Rule

#############################################################################
sub Clear_Rule {
   my ($typ)=@_;
   if ($typ eq 'alias') {
      %ALIAS = ();
   } else {
      my ($cleared,$rule_index) = (0,0);
      foreach $rule_index (@{$TYP{$typ}}) {
         $RULE_LOL[$rule_index][$fTYP] = ''; # disable processing effectively clearing it out
         $RULE_LOL[$rule_index][$fCND] = 'never'; # disable testing
         $RULE_LOL[$rule_index][$fENA] = $FALSE; # disable
         $RULE_LOL[$rule_index][$fPAT] = '*'; # free up some space & provide illegal pattern
         $cleared++;
      }#endforeach
      &Printf2Log("Cleared %d %s entries.\n"),$cleared,$typ;
   }#endif
}#endsub Clear_Rule

#############################################################################
# Enable all rules whose tags match the regular expression $dst.
sub Enable_Rule { # --- ? ? ? ? Bug ? ? ? ? ---
   my ($dst, $flag) = @_;
   my ($tag, $found, $rule_index);
   #$flag = ($flag) ? $TRUE : $FALSE;
   foreach $tag (keys %TAG) {
      if ($tag =~ m{^$dst$}) {
         $found++;
         foreach $rule_index (@{$TAG{$tag}}) {
            next if $RULE_LOL[$rule_index][$fTYP] eq '';
            &Error("Tag failure") if $RULE_LOL[$rule_index][$fTAG] ne $tag;
            $RULE_LOL[$rule_index][$fENA] = $flag;
         }#endforeach
      }#endif
   }#endforeach
   &Debug(0x0100,"ENABLE rule $flag $dst found $found");
   if ($found == 0) {
      &Warn("No matching tags for {$dst}.");
   } else {
      &Printf2Both("%sabled %d occurrence(s) of %s\n",$flag?'En':'Dis',$found,$dst) if &Verbose;
   }#endif
}#endsub Enable_Rule

#############################################################################
sub Add_Rule {
   my (
      $ena, # true, false
      $tag, # <IDENT>
      $typ, # @TYP
      $cnd, # {if, unless, post, always, never}
      $cmp, # {equals, contains, firstword, words, matches}
      $pat, # <PATTERN>
      $mul, # 0, <COUNT>
      $ctx, # <IDENT> context to match
      $cty, # <IDENT> new context
      $inc, # <FILE>
      $act, # {enable, disable}
      $ds0, # <IDENT>
      $dst, # <IDENT>
      $msg, # "found $&"
      $cnt, # 0..
      $min, # '', <COUNT>
      $max, # '', <COUNT>
      $sho, # 0, <COUNT>
      $frc, # false, true
      $and, # '', expr
      $alw, # '', expr
      $pre, # '', expr
      $evl, # '', expr
   )=@_;
   my (@THIS_RULE) = &New_Rule($ena,$tag,$typ,$cnd,$cmp,$pat,$mul,$ctx,$cty,$inc,$act,$ds0,$dst,$msg,$cnt,$min,$max,$sho,$frc,$and,$alw,$pre,$evl);
   #Debug(0x0001,"ADDING rule '$typ'");
   my $RULE_REF = [ @THIS_RULE ];
   &Display_Rule(1, $RULE_REF); # display if needed for DEBUG
   push(@RULE_LOL,  $RULE_REF); # for sequential access to rules
   push(@{$TAG{$tag}}, $#RULE_LOL); # for easy access to tags
   push(@{$TYP{$typ}}, $#RULE_LOL); # for easy access to rules
}#endsub Add_Rule

#############################################################################
# Get the regular expression or text -- may be multi-line
#----------------------------------------------------------------------------
sub Parse_Pattern {
   my ($CURR_TXT) = @_;
   my $pat = '';
   my $mul = 0;
   if ($CURR_TXT =~ s/^.//) {
      my $delim = $&;
      $delim = $rh{$delim} if defined $rh{$delim};
      my $delim_index = -1;
      my $local_context = 1;
      while (($delim_index = index($CURR_TXT,$delim)) < 0) {
         $local_context++;
         $pat .= $CURR_TXT."\n";
         ($CURR_TXT,$INCL_LNO) = &Next_Rule_Line($INCL_LNO);
         $RULE_LNO = $INCL_LNO;
         last if &Eof() and length $CURR_TXT;
      }#endwhile
      $required_context = $local_context if $local_context > $required_context;
      $mul = $local_context if $local_context > 1;
      $pat .= substr($CURR_TXT,0,$delim_index);
      while ($pat =~ s/[\$]([A-Za-z]\w*)/\001/ or $pat =~ s/[\$]{([A-Za-z]\w*)}/\001/) {
         my $macro = $main::VAR{$1};
         $pat =~ s/\001/$macro/;
      }#endwhile
      # Remove extracted text
      substr($CURR_TXT,0,$delim_index+1) = '';
   } else {
      &Warn("Missing regular expression in '$kw' rule.");
   }#endif
   return ($pat,$mul,$CURR_TXT);
}#endsub Parse_Pattern

#############################################################################
sub Find_File {
   my ($file)=@_;
   my $path ='';
   if (index('/.',substr($file,0,1)) < 0) { # not a full specification
      my $dir;
      $path = '';
      DIR: foreach $dir (@RULE_PATH) {
         substr($dir,0,2) = $tooldir.'/..' if index($dir,'$0/') == 0;
         next DIR unless -r ($dir.'/'.$file);
         # FOUND!
         $path = ($dir.'/'.$file);
         last DIR;
      }#endforeach
   } elsif (-r $file) {
      $path = $file;
   }#endif
   return $path;
}#endsub Find_File

#############################################################################
sub Alias {
   my ($word) = @_;
   $word = $ALIAS{$word} if defined $ALIAS{$word};
   return $word;
}#endsub Alias

#############################################################################
# This routine fixes Perl expressions passed in to the 'expr', 'and',
# 'eval' and 'allow' rule clauses.
#----------------------------------------------------------------------------
sub Fix_Expr {
   my ($expr) = @_;
   $expr =~ s/[\$](\w\w+)\b/\$main::VAR{'$1'}/g;
   $expr =~ s/[\$]{(\w\w+)}\b/\$main::VAR{'$1'}/g;
   $expr =~ s/[\$][.]/\$INPUT_LNO/g;
   $expr =~ s/[\$][&]/\$FOUND[0]/g;
   $expr =~ s/[\$][+]/\$FOUND[1]/g;
   $expr =~ s/[\$][1]/\$FOUND[2]/g;
   $expr =~ s/[\$][2]/\$FOUND[3]/g;
   $expr =~ s/[\$][3]/\$FOUND[4]/g;
   $expr =~ s/[\$][4]/\$FOUND[5]/g;
   $expr =~ s/[\$][5]/\$FOUND[6]/g;
   $expr =~ s/[\$][6]/\$FOUND[7]/g;
   $expr =~ s/[\$]([A-Za-z])\b/\$main::VAR{'$1'}/g;
   return $expr;
}#endsub Fix_Expr

#############################################################################
sub Parse_Expr {
   my ($CURR_TXT) = @_;
   my $expr = '';
   if ($CURR_TXT =~ s/^[\[\{].// and defined $rh{$&}) {
      my $delim = $&;
      $delim = $rh{$delim};
      my $delim_index = -1;
      while (($delim_index = index($CURR_TXT,$delim)) < 0) {
         $expr .= $CURR_TXT."\n";
         ($CURR_TXT, $INCL_LNO) = &Next_Rule_Line($INCL_LNO);
         $RULE_LNO = $INCL_LNO;
         last if &Eof() and length $CURR_TXT;
      }#endwhile
      $expr .= substr($CURR_TXT,0,$delim_index);
      substr($CURR_TXT,0,$delim_index+2) = '';
   } else {
      &Warn("Missing valid Perl expression in '$kw' rule.");
   }#endif
   $expr = &Fix_Expr($expr);
   $expr =~ s/\\'/\001/g;
   $expr =~ s/'([^'}]*)'/q{$1}/g;
   $expr =~ s/'([^')]*)'/q($1)/g;
   $expr =~ s/\001/\\'/g;
   open(CHECK, "perl -ce '$expr' 2>&1 |");
   my $result = join("\n",<CHECK>);
   close(CHECK);
   &Warn("Invalid Perl expression '$expr': $result") unless $result =~ m/syntax OK/;
   return ($expr,$CURR_TXT);
}#endsub Parse_Expr

#############################################################################
sub Parse_Rule {
   my ($CURR_TXT) = @_;
   my (
      $ena, # true, false
      $tag, # <IDENT>
      $typ, # @TYP
      $cnd, # {if, unless, post, always, never}
      $cmp, # {equals, contains, firstword, words, matches}
      $pat, # <PATTERN>
      $mul, # 0, <COUNT>
      $ctx, # <IDENT> context to m
      $cty, # <IDENT> new context
      $inc, # <FILE>
      $act, # {enable, disable, ''}
      $ds0, # <IDENT>
      $dst, # <IDENT>
      $msg, # "found $&"
      $cnt, # 0..
      $min, # '', <COUNT>
      $max, # '', <COUNT>
      $sho, # 0, <COUNT>
      $frc, # false, true
      $and, # '', expr
      $alw, # '', expr
      $pre, # '', expr
      $evl, # '', expr
   ) = (('') x scalar(@FLD));
   my ($VAR, $VAL);
   &Debug(0x0008,"PARSING RULE: '%s'",$CURR_TXT);
   return if $CURR_TXT =~ m:^\s*((#|(//)|(--)).*)?$:; # skip comments
   $CURR_TXT =~ s/^\s+//; # remove leading whitespace
   my $ORIG_TXT = $CURR_TXT; # for error messages
   # Pull off context tags if any
   $tag = ($CURR_TXT =~ s/^([_a-zA-Z]\w*):\s*//) ? $1 : $RULE_FILE.'//'.$RULE_LNO;
   $kw = '';
   if ($CURR_TXT =~ m/^[\$](\w+)\s*=s*/) {
      # Grab variable assignments
      ($VAR, $VAL) = ($1,$');
      $VAL =~ s/^[\[{"'](.*)['"}\]];?$/$1/; # Remove quoting
      $VAL =~ s{^q{1,2}[\[{"'/](.*)[/'"}\]];?$}{$1}; # Remove quoting
      $main::VAR{$VAR} = $VAL;
      return 1;
   } elsif ($CURR_TXT =~ s/^([a-zA-Z]+)\b//) {
      # Grab keywords
      $kw = &Alias($1);
      &Debug(0x0002,"PARSING RULE KW = $kw\n");
   } else {
      &Warn("Unrecognized command!\n?'$ORIG_TXT'");
      return 0;
   }#endif
   if (grep($kw eq $_, @ENA) and $CURR_TXT =~ s/^\s+(\S+)\s+(\w+)\s+/ $2 /) {
      # Grab enable/disable pattern with conditional
      ($ds0,$cnd) = ($1,&Alias($2));
   } elsif (grep($kw eq $_, @INC) and $CURR_TXT =~ s/^\s+"(\S+)"\s+(\w+)\s+/ $2 /) {
      # Grab use/require/include file with conditional
      ($inc,$cnd) = ($1,&Alias($2));
   } elsif ($CURR_TXT =~ m/^\s+(\w+)\s+/) {
      # Grab conditional if bare
      $cnd = &Alias($1);
   }#endif
   if (defined $disallow{$kw}) {
      &Warn("Disallowed command: '$kw'");
      return 0;
   #------------------------------------------------------------------------
   } elsif (grep($kw eq $_, @TYP) and grep($cnd eq $_,@CND)) {
      #--------------------------------------------------------------------
      # Parse pattern rule
      #--------------------------------------------------------------------
      $typ = $kw;
      $CURR_TXT =~ s/^\s+(\w+)\s+//;
      &Debug(0x0002,"PARSING '$kw $cnd' pattern rule");
      if ($CURR_TXT =~ m/^(\w+)\s*/ and $cmp = &Alias($1) and grep($cmp eq $_,@CMP)) {
         $CURR_TXT =~ s/^\w+\s*//;
      } elsif ($cnd eq 'post') {
         $cmp = 'always';
      } else {
         &Warn("Unknown comparison '$&'.\n?'$ORIG_TXT'");
         return 0;
      }#endif
      &Debug(0x0002,"PARSING '$cmp' comparison");
      if ($cmp eq 'expr') {
           ($and,$CURR_TXT) = &Parse_Expr($CURR_TXT);
      } elsif ($cnd ne 'post') {
           ($pat,$mul,$CURR_TXT) = &Parse_Pattern($CURR_TXT);
      }#endif
      # Handle actions
      while ($CURR_TXT =~ s/^\s*(\w+)\s+// or $CURR_TXT =~ s/^\s*(#).*//) {
         my ($action) = &Alias($1);
         next if $action eq '#'; # skip trailing comments
         &Debug(0x0002,"PARSING '$action' action");
         if ($action eq 'msg') {
            if ($CURR_TXT =~ s/^"([^"]+)"\s*//) {
               $msg = $1;
            } else {
               &Warn("Illegal text syntax for '$action' in rule - must enclose in double quotes.\n?'$ORIG_TXT'");
               return 0;
            }#endif
         } elsif ($action eq 'and') {
            ($and,$CURR_TXT) = &Parse_Expr($CURR_TXT);
         } elsif ($action eq 'goto') {
            if ($CURR_TXT =~ s/^(\S+)\s*//) {
               $cty = $1;
            } else {
               &Warn("Illegal tag syntax for '$action' in rule.\n?'$ORIG_TXT'");
               return 0;
            }#endif
         } elsif ($action eq 'context') {
            if ($CURR_TXT =~ s/^(\S+)\s*//) {
               $ctx = $1;
            } else {
               &Warn("Illegal tag syntax for '$action' in rule.\n?'$ORIG_TXT'");
               return 0;
            }#endif
         } elsif ($action eq 'only') {
            if ($CURR_TXT =~ s/^(\d+)\s*//) {
               $min = $1;
               $max = $1;
            } else {
               &Warn("Illegal tag syntax for '$action' in rule.\n?'$ORIG_TXT'");
               return 0;
            }#endif
         } elsif ($action eq 'min') {
            if ($CURR_TXT =~ s/^(\d+)\s*//) {
               $min = $1;
            } else {
               &Warn("Illegal tag syntax for '$action' in rule.\n?'$ORIG_TXT'");
               return 0;
            }#endif
         } elsif ($action eq 'max') {
            if ($CURR_TXT =~ s/^(\d+)\s*//) {
               $max = $1;
            } else {
               &Warn("Illegal tag syntax for '$action' in rule.\n?'$ORIG_TXT'");
               return 0;
            }#endif
         } elsif ($action eq 'pre') {
            &Warn("Rule has 'pre' clause");
            ($pre,$CURR_TXT) = &Parse_Expr($CURR_TXT);
         } elsif ($action eq 'eval') {
            ($evl,$CURR_TXT) = &Parse_Expr($CURR_TXT);
         } elsif ($action eq 'allow') {
            ($alw,$CURR_TXT) = &Parse_Expr($CURR_TXT);
         } elsif ($action eq 'show') {
            if ($CURR_TXT =~ s/^(\d+)(\s+more(\s+lines?))?\s*//) {
               $sho = $1;
            } else {
               &Warn("Illegal tag syntax for '$action' in rule.\n?'$ORIG_TXT'");
               return 0;
            }#endif
         } elsif ($action eq 'enable' or $action eq 'disable') {
            $act = $action;
            if ($CURR_TXT =~ s/^(\S+)\s*//) {
               $dst = $1;
            } else {
               &Warn("Illegal tag syntax for '$action' in rule.\n?'$ORIG_TXT'");
               return 0;
            }#endif
         } elsif ($action eq 'include' or $action eq 'require' or $action eq 'use') {
            if ($CURR_TXT =~ s/^(\S+)\s*//) {
               my $inc = $1;
            } else {
               &Warn("Illegal tag syntax for '$action' in rule.\n?'$ORIG_TXT'");
               return 0;
            }#endif
         } elsif ($action eq 'always') {
            $frc = 1;
         } else {
            &Warn("Illegal action '$action' in rule.\n?'$ORIG_TXT'");
            return 0;
         }#endif
      }#endwhile
      if ($CURR_TXT =~ m/^\s*(#.*)?$/) {
         &Add_Rule($ena,$tag,$typ,$cnd,$cmp,$pat,$mul,$ctx,$cty,$inc,$act,$ds0,$dst,$msg,$cnt,$min,$max,$sho,$frc,$and,$alw,$pre,$evl);
      } else {
         &Warn("Illegal syntax for '$kw' rule.\n?'$ORIG_TXT'");
         return 0;
      }#endif
   #------------------------------------------------------------------------
   } elsif ($kw eq 'define') {
      &Debug(0x0002,"PARSING macro definition");
      if ($CURR_TXT =~ s/^\s+[\$]?(\w+)\s+//) {
         ($VAR, $VAL) = ($1,$');
         $VAL =~ s/^[\[{"'](.*)['"}\]]$/$1/; # Remove quoting
         $main::VAR{$VAR} = $VAL;
      } else {
         &Warn("Illegal syntax for define macro\n?'$ORIG_TXT'");
      }#endif
      return 0;
   #------------------------------------------------------------------------
   } elsif ($kw eq 'include' or $kw eq 'require' or $kw eq 'use') {
      if ($CURR_TXT =~ s/^\s+"(\S+)"\s*$//) {
         my $file = $1;
         &Debug(0x0002,"PARSING file inclusion command");
         # search for file
         my $path = &Find_File($file);
         if ($path ne '') {
            &Reset_Rules if $kw eq 'use'; # use starts out clean
            &Printf2Log("*** Use $path.\n") if $kw eq 'use';
            &Include($path);
         } elsif ($kw ne 'include') {
            &Warn("Missing required file '$file' for $kw.");
            return 0;
         }#endif
      } else {
         &Warn("Illegal syntax for '$kw' rule.\n?'$ORIG_TXT'");
         return 0;
      }#endif
   #------------------------------------------------------------------------
   } elsif ($kw eq 'enable' or $kw eq 'disable') {
      if ($CURR_TXT =~ s/^\s+(\S+)\s*//) {
         $dst = $1;
         &Debug(0x0002,"PARSING enable/disable command");
         if ($CURR_TXT =~ s/^(if)\s+//) {
            # Parse conditional
            $typ = $kw;
            $cnd = $1;
            if ($CURR_TXT =~ m/^(\w+)\s*/ and $cmp = &Alias($1) and grep($cmp eq $_,@CMP)) {
               $CURR_TXT =~ s/$cmp\s*//;
            } else {
               &Warn("Unknown comparison '$&'.\n?'$ORIG_TXT'");
               return 0;
            }#endif
            ($pat,$mul,$CURR_TXT) = &Parse_Pattern($CURR_TXT);
            if ($CURR_TXT =~ s/^msg\s+"([^"]+)"\s*$//) {
               $msg = $1;
            }#endif
            if ($CURR_TXT =~ m/^\s*$/) {
               &Add_Rule($ena,$tag,$typ,$cnd,$cmp,$pat,$mul,$ctx,$cty,$inc,$act,$dst,$msg,$cnt,$min,$max,$sho,$frc,$and,$alw,$pre,$evl);
            } else {
               &Warn("Illegal syntax for '$kw' rule.\n?'$ORIG_TXT'");
               return 0;
            }#endif
         } else {
            # Do it now!
            $flag = ($kw eq 'enable') ? $TRUE : $FALSE;
            &Enable_Rule($dst,$flag);
         }#endif
      } else {
         &Warn("Illegal syntax for '$kw' rule.\n?'$ORIG_TXT'");
         return 0;
      }#endif
   #------------------------------------------------------------------------
   } elsif ($kw eq 'disallow') {
      &Debug(0x0002,"PARSING disallow command");
      if ($CURR_TXT =~ m/^(\s+[a-zA-Z]+)+\s*$/) {
         while ($CURR_TXT =~ s/^\s+([a-zA-Z]+)//) {
            $disallow = $1;
            if (grep($disallow eq $_,@DIS)) {
               $disallow{$disallow} = 1;
            } else {
               &Warn("Not permitted to disallow '$disallow'.");
               return 0;
            }#endif
         }#endwhile
      } else {
         &Warn("Illegal syntax for '$kw' rule.\n?'$ORIG_TXT'");
         return 0;
      }#endif
   #------------------------------------------------------------------------
   } elsif ($kw eq 'alias') {
      &Debug(0x0002,"PARSING alias command");
      if ($CURR_TXT =~ m/^\s+(\w+)\s*=\s*(\w+)\s*$/) {
         my ($fm,$to) = ($1,$2);
         if (grep($to,(@TYP,@DIS)) and !defined $ALIAS{$fm}) {
            $ALIAS{$fm} = $to;
         } elsif (defined $ALIAS{$fm}) {
            &Warn("May not redefine alias '$fm'.");
            return 0;
         } else {
            &Warn("Illegal alias $fm=$to!\n?'$ORIG_TXT'");
            return 0;
         }#endif
      } else {
         &Warn("Illegal syntax for '$kw' rule.\n?'$ORIG_TXT'");
         return 0;
      }#endif
   #------------------------------------------------------------------------
   } elsif ($kw eq 'clear') { # clear rules matching text
      &Debug(0x0008,"PARSING clear command");
      if ($CURR_TXT =~ m/^(\s+[a-zA-Z]+)+\s*$/) {
         while ($CURR_TXT =~ s/^\s+([a-zA-Z]+)//) {
            &Clear_Rule($1);
         }#endwhile
      } else {
         &Warn("Illegal syntax for '$kw' rule.\n?'$ORIG_TXT'");
         return 0;
      }#endif
   #------------------------------------------------------------------------
   } elsif ($kw eq 'verbose' or $kw eq 'quiet') { # set verbosity
      &Debug(0x0002,"PARSING verbose/quiet command");
      if ($CURR_TXT =~ m/^\s*$/) {
         $verbosity = 'quiet';
      } else {
         &Warn("Illegal syntax for '$kw' rule.\n?'$ORIG_TXT'");
         return 0;
      }#endif
   #------------------------------------------------------------------------
   } elsif ($kw eq 'DEBUG') {
      &Debug(0,"PARSING DEBUG command.");
      if ($CURR_TXT =~ m/^\s+(\d+)\s*$/) { # DEBUG not documented
         $DEBUG = $1;
         $DEBUG = hex($DEBUG) if $DBUG =~ m/x/;
      } else {
         &Warn("Illegal syntax for '$kw' rule.\n?'$ORIG_TXT'");
         return 0;
      }#endif
   #------------------------------------------------------------------------
   } elsif ($kw eq 'log') { # set log file name
      &Debug(0x0002,"PARSING log command");
      if ($CURR_TXT =~ s/^\s+(\S+)\s*$//) {
         &Create_Rpt($1);
      } else {
         &Warn("Illegal syntax for '$kw' rule.\n?'$ORIG_TXT'");
         return 0;
      }#endif
   #------------------------------------------------------------------------
   } elsif ($kw eq 'echo') {
      &Debug(0x0002,"PARSING echo command");
      if ($CURR_TXT =~ m/^\s+"(.*)"$/) {
         my ($echo_text) = '|'.$1;
         push(@ECHO,$echo_text) if $only_rules;
         &Printf2Both("%s\n",$echo_text);
      } else {
         &Warn("Illegal syntax for '$kw' rule.\n?'$ORIG_TXT'");
         return 0;
      }#endif
   #------------------------------------------------------------------------
   } elsif ($kw eq 'version') {
      &Debug(0x0002,"PARSING version command");
      if ($CURR_TXT =~ m/^\s+(\d+\.\d+)$/) {
         $reqd = $1;
         &Fatal("Version $$revs < $reqd.") if $$revs < $reqd and !$only_rules;
      } else {
         &Warn("Illegal syntax for '$kw' rule.\n?'$ORIG_TXT'");
         return 0;
      }#endif
   #------------------------------------------------------------------------
   } elsif ($kw eq 'show') {
      &Debug(0x0002,"PARSING show command");
      if ($CURR_TXT =~ m/^\s+(\d+)$/) { # specified min limit
         $show_min = $1;
      } else {
         &Warn("Illegal syntax for '$kw' rule.\n?'$ORIG_TXT'");
         return 0;
      }#endif
   #------------------------------------------------------------------------
   } elsif ($kw eq 'limit') {
      &Debug(0x0002,"PARSING limit command");
      if ($CURR_TXT =~ m/^\s+(\d+)\.\.(\d+)$/) { # specified full range
         &Required_Context($1,$2);
      } elsif ($CURR_TXT =~ m/^\s+(\d+)$/) { # specified min limit
         &Required_Context($1,&max($1,$max_context));
      } elsif ($CURR_TXT =~ m/^\s+(\d+)\.\.$/) { # specified min limit
         &Required_Context($1,max($1,$max_context));
      } elsif ($CURR_TXT =~ m/^\s+\.\.(\d+)$/) { # specified max limit
         &Required_Context($1,&min($1,$min_context));
      } else {
         &Warn("Illegal syntax for '$kw' rule.\n?'$ORIG_TXT'");
         return 0;
      }#endif
#   #------------------------------------------------------------------------
#   } elsif ($kw eq 'glob') {
#       if ($CURR_TXT =~ m/^\s+(\S+)$/) {
#           $glob = $1;
#       } else {
#           &Warn("Illegal syntax for '$kw' rule.\n?'$ORIG_TXT'");
#           return 0;
#       }#endif
   #------------------------------------------------------------------------
   } else {
      &Warn("Unrecognized rule!\n?'$ORIG_TXT'");
      return 0;
   }#endif
   return 1;
}#endsub Parse_Rule

#############################################################################
sub Include {
   my ($file_name)=@_;
   my $rules_read = 0;
   my ($INCL_POSN);
   local *INCL_HNDL; # not my!
   if ($INCL_FILE ne '') { # push old file on stack
      $INCL_POSN = tell INCL_HNDL;
      close(INCL_HNDL);
      push(@INCL_POSN, $INCL_POSN);
      push(@INCL_FILE, $INCL_FILE);
      push(@INCL_LNO, $INCL_LNO);
   }#endif
   open(INCL_HNDL, "<$file_name") or &Die("Unable to read rules from $file_name");
   &Printf2Both("INFO: Reading $file_name\n");
   $RULE_FILE = $INCL_FILE = $file_name;
   $RULE_LNO = $INCL_LNO = $.;
   my $next_line;
   ($next_line,$INCL_LNO) = &Next_Rule_Line($INCL_LNO);
   $RULE_LNO = $INCL_LNO;
   if ($next_line =~ m/^#!/ and $next_line =~ /\bperl\b/) {
      close(INCL_HNDL);
      require $file_name;
   } else {
      $rules_read += &Parse_Rule($next_line);
      while (!eof(INCL_HNDL)) {
         ($next_line,$INCL_LNO) = &Next_Rule_Line($INCL_LNO);
         $RULE_LNO = $INCL_LNO;
         $rules_read += &Parse_Rule($next_line);
      }#endwhile <INCL_HNDL>
      close(INCL_HNDL);
   }#endif
   if (@INCL_POSN) { # return to previous file
      $INCL_POSN = pop(@INCL_POSN);
      $RULE_FILE = $INCL_FILE = pop(@INCL_FILE);
      $RULE_LNO = $INCL_LNO = pop(@INCL_LNO);
      open(INCL_HNDL, "<$INCL_FILE") or &Die("Unable to read rules from $$INCL_FILE");
      seek INCL_HNDL,$INCL_POSN,0;
      $. = $INCL_LNO;
   } else {
      $RULE_FILE = $INCL_FILE = '';
      $RULE_LNO = $INCL_LNO = 0;
   }#endif
   return $rules_read;
}#endsub Include

#############################################################################
sub Read_Rules {
   return if defined $rules_read;
   $start = time();
   foreach $dir (@RULE_PATH) {
      substr($dir,0,2) = $tooldir.'/..' if index($dir,'$0/') == 0;
      $path = $dir.'/'.$KIND.$EXTN;
      $path = $dir.'/'.$KIND unless -r $path;
      next unless -r $path;
      &Include($path) and $rules_read = $TRUE;
   }#endforeach
   # Sort rules to enforce evaluations before all else
   my @SORTED;
   foreach $RULE (@RULE_LOL) {
      push @SORTED, $RULE if $RULE->[$fTYP] ne 'eval';
   }#endfor
   foreach $RULE (@RULE_LOL) {
      push @SORTED, $RULE if $RULE->[$fTYP] eq 'eval';
   }#endfor
   @RULE_LOL = @SORTED;
   &Printf2Both("INFO: Compiled %s rules in %s\n",scalar(@RULE_LOL),&Format_Time(time()-$start));
}#endsub Read_Rules

###########################################################################
}#end BEGIN

__DATA__

__INSTALL__
---------------------------------------------------------------------------
__PERL__ unlink 'INSTALL'
__PERL__ chmod ((stat($0))[3]|0555),$0;
__PERL__ unlink $tool if (-l $tool);
__PERL__ symlink $0,$tool unless -e $tool;
__EXEC__ $toolpath -q -V -man
__EXEC__ $toolpath -q -XT MANIFEST
__EXEC__ $toolpath -q -XT README
__EXEC__ $toolpath -q -XT HISTORY
__EXEC__ $toolpath -q -XT INSTALLATION
__EXEC__ $toolpath -q -XT LICENSE
---------------------------------------------------------------------------
You may now move $tool.1 to the appropriate manpage
directory (typically ../man/man1/). Also, check that
$TOOL is executable and points to the correct version.
---------------------------------------------------------------------------
__EOF__

__TEST.SH__
__EXEC__ chmod 755 test.sh
#! /bin/sh
#--------------------------------------------------------------------------
# Regression test script
#--------------------------------------------------------------------------
logscan
logscan -?
logscan -h
logscan -man
logscan -XT test.sh      \
      -XT test.rules   \
      -XT sample1.log  \
      -XT sample2.log  \
      -XT all.rules    \
      -XT nil.rules    \
      -XT killer.log   \
      THE-END
logscan -V
logscan -v -k all -d compiled.rules
logscan NO_SUCH_FILE
logscan -k test sample1.log
logscan -k test sample2.log
logscan -INSTALL
#- END ----------------------------------------------------------------------
__EOF__

__TEST.RULES__
#############################################################################
# A ruleset for testing logscan
echo "Basic logscan test.rules"
echo "- Expect 0 fatals 1 severe  2 errors 1 warning  for sample1.log"
echo "- Expect 1 fatals 2 severes 2 errors 3 warnings for sample2.log"
severe unless contains "Test revision 1.1"
ABORT: severe if matches /^ABORT\b/                                  
note if matches /Dont abort/ disable ABORT
NONZERO:  context if firstword "compile"
NONZERO:  context if firstword "link"                           
NONEMPTY: context if firstword "find"
error if matches /^0$/  msg "Command failed" context NONZERO  
error if matches /^{}$/ msg "Command failed" context NONEMPTY 
KEYWORD: context if firstword "if"                             
warning unless words "descriptions" min 2 max 3
warning unless contains "There" min 2 max 2
warning expect word "part" only 2
warning if contains "latch"                           
fatal if contains 'very fatal' message "Intentional fatal"
severe unless contains " END " msg "Never finished"
# END #######################################################################
__EOF__

__SAMPLE1.LOG__
-----------------------------------------------------------------------------
There are many insignificant lines such as
descriptions of the Quick brown fox who jumped
over the lazy dog. The tool should not pickup
on any of these lines as errors; although, sometimes
it might consider them as part of the context
to satisfy minimum context.

This is Test revision 1.1
find you
There are many insignificant lines such as descriptions of the Quick
brown fox who jumped over the partly lazy dog. The tool should not pickup on
any of these lines as errors; although, sometimes it might consider them
as part of the context to satisfy minimum context.
{you are here}
find self
{}
link
0
compile
Some text is almost completely random
whereas other lines are significant to
the engineer.
Found dangling if, so latch inferred
1
ABORT: End of good sample

Won't get here...
Now is the good time for all bad men
to come to the aid of their fellow
criminal and end this reign of terror
and violence towards fellow men..
-- END ----------------------------------------------------------------------
__EOF__

__SAMPLE2.LOG__
-----------------------------------------------------------------------------
There are many insignificant lines such as
descriptions of the Quick brown fox who jumped
over part of the lazy dog. The tool should not pickup
on any of these lines as errors; although, sometimes
it might consider them as part of the context
to satisfy minimum context.

Dont abort

This is Test revision 1.0
find you
There are many insignificant lines such as descriptions of the Quick
brown fox who jumped over the lazy dog. The tool should not pickup on
any of these lines as errors; although, sometimes it might consider them
as part of the context to satisfy minimum context.
{you are here}
find self
{}
link
0
compile
Some text is almost completely random
whereas other lines are significant to
the engineer.
Found dangling if, so latch inferred
1
ABORT: End of bad sample

Now is the good time for all bad men
to come to the aid of their fellow
criminal and end this reign of terror
and violence towards fellow men..

There are many descriptions 
of descriptions.

This should be very fatal.

-- END ----------------------------------------------------------------------
__EOF__

__NIL.RULES__
# Nothing
__EOF__

__ALL.RULES__
#############################################################################
# Try all commands
#----------------------------------------------------------------------------
// all comments
-- all styles
verbose
ignore  if     matches   /never mind/
fatal   if     firstword "ABORT"
severe  if     contains "core dump"
error   if     matches   /^ERROR:/
warning unless equals   "Revison 1.5"
alert   if     contains  "WARNING:"
info    if     word "infer"
note    if     firstword "INFO:"
count   if     firstword "stamp" and {= $1 > 4.1 =}
CMD: context if firstword /compile/
use test.rules
require nil.rules
include nil.rules
alias goof=error
alias oops = warning
enable CMD
disable CMD
clear CMD
disallow alias
alias never=fatal
DEBUG 5
quiet
# END #######################################################################
__EOF__

__KILLER.RULES__
error if matches /clear/reset/
alias you = me
bogus rule
__EOF__

__KILLER.LOG__
#----------------------------------------------------------------------------
# This is a killer log file
# never mind ABORT
got a core dump here
this is not an ERROR:
compile THIS is context A
ERROR: this IS an error
compile THIS is context B
could infer latches
count this time stamp
INFO: this is some info
this is not INFO:
count another time stamp
ABORT this line
Never get here
#- END ----------------------------------------------------------------------
__EOF__

__TEMPLATE.RULES__
#!/usr/local/bin/logscan -k TEMPLATE
#
# @(#)$Info: Rules defining TEMPLATE. $
#
echo "********************************************************************"
echo "* @(#)#Id$ *"
echo "********************************************************************"
echo ""
echo "This is a TEMPLATE rules file."
echo ""
echo "********************************************************************"

#==========================================================================
# TEMPLATE
#--------------------------------------------------------------------------
TEMPLATE: context if firstword "TEMPLATE"
ignore  if matches  /TEMPLATE/
fatal   if matches  /TEMPLATE/
error   if matches  /TEMPLATE/ context TEMPLATE
warning if contains /TEMPLATE/
error unless contains "TEMPLATE"
__EOF__

__SYNOPSYS.RULES__
#!/usr/local/bin/logscan -k synopsys
# Rules defining good Synopsys log file output
echo "********************************************************************"
echo "* @(#)#Id$ *"
echo "********************************************************************"
echo ""
echo "WARNING: This is a sample rules file for Synopsys design compiler."
echo "         please use at your own risk"
echo ""
echo "********************************************************************"

# Define the minimum context to show
limit 6..12

 TIMESTAMP: context if firstword "TIMESTAMP("
 COMMAND:   context if matches /^% (\w+)/

# General rules
 error   if matches   /\([A-Z]+-\d+\)/ show 5
 error   if matches   /^Error.*/ show 5
 error   if matches   /^ERROR.*/ show 5
 error   if matches   /^Warning.*/ show 5
 error   if matches   /^WARNING.*/ show 5
# Especially nasty stuff
 fatal   if matches   /^ABORT.*/ show 1
 fatal   if matches   /^getfatal:/ show 7 msg "dc_shell fatal detected!"
 severe  if contains  "Error: EOF found before command was complete"
 severe  if matches   /Error: could not close script file ".*/

# Dangerous INFO
 warning if matches   /^INFO: Command \w+ returned 0/
 ignore  if contains  "INFO: Command check_error returned 0"
 warning if contains  "INFO: Command check_error returned 1"

 warning if contains  "WARNING: Applying environmental override"
 warning if contains  "WORKAROUND" show 3

# Stuff we can safely ignore
 # Ignore duplicates due to multi-line messages
 ignore  if contains   "(HDL-307)"
 ignore  if firstword "Information:"
 ignore  if contains  "(CMD-013)"
 ignore  if contains  "(DDB-24)"
 ignore  if contains  "(DDB-74)"
 # 2nd line of a multi-line informational message
 ignore  if contains  "(DWSC-9)"
 ignore  if contains  "(HDL-410)"
 ignore  if contains  "(HLS-238)"
 # 2nd line of a multi-line informational message
 ignore  if contains  "(HLS-254)"
 ignore  if contains  "(OPT-933)"
 ignore  if contains  "(SYNH-2)"
 ignore  if contains  "(SYNH-3)"
 # Overwriting previously specified port
 ignore  if contains  "(TESTDB-257)"
 # 2nd line of a multi-line informational message
 ignore  if contains  "(UI-58)"
 ignore  if contains  "(UID-348)"
 ignore  if contains  "(VER-129)"
 ignore  if contains  "(VER-130)"
 ignore  if contains  "Warning: The '-update' option is disabled for Presto HDLC analyzed units."
 ignore  if contains  "Warning: Design rule attributes from the driving cell will be"
 ignore  if contains   "(UID-401)"
 ignore  if contains  "Warning: Ignoring compile_default_critical_range = 0. (UIO-62)"
 ignore  if contains  "Warning: Verilog 'assign' or 'tran' statements are written out. (VO-4)"
 ignore  if contains  "Warning: Changed wire name"
 warning if contains  "Warning: The output of the propagate_constraints command is in DCSH mode.  Use the UNIX utility dc-transcript to convert DCSH script to DC-Tcl script. (UID-486)"

#==========================================================================
# Expectations
#--------------------------------------------------------------------------
# Make sure we use the right tools and complete gracefully
 error unless matches /Version (\d+\.\d+)/ and {=$1 > 2000.11=} msg "Expecting 2000.11 or better"
 fatal unless contains "Thank you..." only 1

#- END synopsys.rules -----------------------------------------------------
__EOF__

__LOGSCAN.VIM__
" Vim syntax file
" Language:	Logscan rule file
" Maintainer:	David C Black <dcblack@hldwizard.com>
" Last Change:	2001 Sep 3
"
" Using vim 6.0 simply drop this file into $HOME/.vim/syntax/ directory
" Add :autocmd Syntax logscan source $HOME/.vim/syntax/logscan.vim to
" $HOME/.vim/filtypes.vim
" Add :augroup filetype within :augroup filetype too.

" Remove any old syntax stuff hanging around
syn clear

set errorformat="%t%*[A-Z] %f, %l: %m"
set errorfile=logscan.rpt
set iskeyword=@,48-57,_,192-255
syn keyword logscanKeywords   warning error severe fatal note info
syn keyword logscanKeywords   ignore count echo alert context if unless
syn keyword logscanKeywords   \contains matches firstword msg include
syn keyword logscanKeywords   require use equals exactly alias expect
syn keyword logscanKeywords   always only show enable disable allow goto
syn keyword logscanKeywords   disallow min max limit eval and clear expr
syn keyword logscanKeywords   verbose quiet log debug
syn match   logscanIdentifier  "\<[A-Z][A-Z0-9_]\+\>"
syn region  logscanString start=+"+  end=+"+  
syn region  logscanString start=+/+  end=+/+  
syn region  logscanString start=+{+  end=+}+  

" The logscan header is recognized starting with a "keyword:" line and ending
" with an empty line or other line that can't be in the header.
" All lines of the header are highlighted
" For "From " matching case is required, not for the rest.
syn region	logscanHeader	start="^RULE_PATH " skip="^[ \t]" end="^[-A-Za-z0-9/]*[^-A-Za-z0-9/:]"me=s-1 end="^[^:]*$"me=s-1 end="^---*" contains=logscanHeaderKey

syn case ignore

syn region	logscanHeader	start="^\(INFO:\|ERROR:\|WARNING:\|FATAL:\|SEVERE:\|NOTE:\|EXPECTED:\)" skip="^[ \t]" end="^[-a-z0-9/]*[^-a-z0-9/:]"me=s-1 end="^[^:]*$"me=s-1 end="^---*" contains=logscanHeaderKey

syn match	logscanEmail	contained "[_=a-z\.+A-Z0-9-]\+@[a-zA-Z0-9\./\-]\+"
syn match	logscanEmail	contained "<.\{-}>"

" even and odd quoted lines
" removed ':', it caused too many bogus highlighting
" order is imporant here!
syn match	logscanQuoted1	"^[\t ]*#.*"
syn match	logscanLabel   "^[\t ]*\<[A-Z][A-Z0-9_]\+\>:"

" Need to sync on the header.  Assume we can do that within a hundred lines
syn sync lines=10

if !exists("did_logscan_syntax_inits")
  let did_logscan_syntax_inits = 1
  " The default methods for highlighting.  Can be overridden later
  hi link logscanHeader		Statement
  hi link logscanQuoted1	Comment
  hi link logscanEmail		Special
  hi link logscanKeywords       Statement
  hi link logscanIdentifier     Identifier
  hi link logscanLabel          Type
  hi link logscanString         String
endif

let b:current_syntax = "logscan"

__EOF__
__LOG.VIM__
" Vim syntax file
" Language:	Logscan report file
" Maintainer:	David C Black <dcblack@hldwizard.com>
" Last Change:	2001 Sep 3

" Remove any old syntax stuff hanging around
syn clear

set iskeyword=@,48-57,_,192-255

syn case ignore

syn match  logEmail contained "[_=a-z\.+A-Z0-9-]\+@[a-zA-Z0-9\./\-]\+"
syn match  logEmail contained "<.\{-}>"
syn match  logQuoted1 "^\s*#.*"
syn match  logFatal   "^ABORT.*"
syn match  logFatal   "^Abort.*"
syn match  logFatal   "^FATAL.*"
syn match  logFatal   "^Fatal.*"
syn match  logError   "^ERROR.*"
syn match  logError   "^Error.*"
syn match  logError   "^SEVERE.*"
syn match  logError   "^Severe.*"
syn match  logWarning "^WARNING.*"
syn match  logWarning "^Warning.*"
syn match  logInfo    "^INFO.*"
syn match  logInfo    "^Info.*"
syn match  logInfo    "^NOTE\>.*"
syn match  logInfo    "^Note\>.*"
syn region logString  start=+"+  end=+"+  

if !exists("did_log_syntax_inits")
  let did_log_syntax_inits = 1
  " The default methods for highlighting.  Can be overridden later
  hi logError   ctermfg=red     ctermbg=white guifg=red     guibg=white gui=bold
  hi logWarning ctermfg=darkred ctermbg=white guifg=darkred guibg=white gui=bold
  hi logInfo ctermfg=blue    ctermbg=white guifg=blue    guibg=white gui=bold
  hi link logFatal      logError
  hi link logQuoted1    Comment
  hi link logEmail      Special
  hi link logString     String
endif
let b:current_syntax = "log"

__EOF__

__MANIFEST__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
MANIFEST

Copyright 1997-2001,2008 by David C. Black. All rights reserved.

This distribution should have the following files:

   logscan-VERSION      -- the actual tool, a PERL 5.0 script (*)
   logscan-VERSION.asc  -- a PGP signature of the file
   logscan.pdf          -- PDF document (**)
   MANIFEST             -- this text file listing the files
   README               -- a brief overview of logscan
   HISTORY              -- history of changes
   INSTALLATION         -- a brief installation note
   LICENSE              -- a copy of the licensing terms

See INSTALLATION for notes on how to install.

*  PERL is a free programming language available over the Internet.
   To obtain PERL via the web see:
     <http://www.perl.com/pace/pub/perldocs/latest.html>
** PDF documents are readable with Adobe Acrobat Reader 3.01 or better.
   To obtain Acrobat Reader via the web see:
     <http://www.adobe.com/prodindex/acrobat/readstep.html>

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
__EOF__

__LICENSE__
LICENSE

Copyright 1997-2001,2008 by David C. Black. All rights reserved.

This software, logscan,  is CharityWare in the manner of  Bram Moolenaar's vim
text editor (Vi IMproved) available from <http://www.vim.org>. You may use and
copy it as  much as you like, but  you are encouraged to make a  donation to a
non-profit charity organization addressing poverty-hunger, poverty-housing, or
racial justice. Payment should be made directly to the charity of your choice.

Suggested    non-profit   charitable    organizations    are   Church    World
Service   (sponsors   of   CROP   Walk)   <http://www.churchworldservice.org>,
Habitat    for   Humanity    <http://www.hfh.org>,   Food    for   the    Poor
<http://www.foodforthepoor.org>, or the Interfaith Hospitality Network (Family
Promise) <http://www.nihn.org>.

If you have questions regarding this  license agreement, you may contact me at
+1-512-288-3783. Additional  information about  me can  be found  via the  URL
<http://dcblack.hldwizard.com>

Redistribution in source and binary  forms is permitted provided that verbatim
copies of this copyright notice and this license agreement are included in all
direct and  derived forms and  that any documentation,  advertising materials,
and other materials related to such distribution acknowledge that the software
was developed by David C. Black.

THIS SOFTWARE  IS PROVIDED "AS  IS" AND  WITHOUT ANY EXPRESS  OR IMPLIED
WARRANTIES,  INCLUDING, WITHOUT  LIMITATION, THE  IMPLIED WARRANTIES  OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

Never-the-less,  you  are  encouraged  to  send bug  reports  to  David  Black
(mailto:dcblack@hldwizard.com). Registered  users may expect some  support for
severe bugs as determined by me.  Enhancements and/or feature requests will be
noted; however,  no commitments  will be  made. There  are no  guarantees that
response will be timely. Please include the word LOGSCAN in the Subject header
of your e-mail.

VERIFICATION

All valid  releases of  this tool  are accompanied with  a PGP  signature file
logscan.pgp to verify you have an  unmodified copy. Also, the license file may
be extracted as a PGP signed document.
__EOF__

__HISTORY__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
HISTORY (released versions)

VERSION 2.49
- Documentation issues corrected

VERSION 2.48
- Force output to flush properly

VERSION 2.47

- Fixed bugs with enable/disable conditionals
- Added -j (justify) and -D0xHHHH (debug) options
- Revised licensing
- Added logscan.vim & log.vim syntax files
- Added -html option using vim 6.0!

VERSION 2.44

- Fixed bug with counting report
- Added feature to report total counts
- Clarified documentaton of min/max/unless

VERSION 2.42

Major enhancements added
- Improved documentation (better explanations and examples)
- Documented internal variables used with messages.
- Added 'expect' and 'allow' conditional clauses
- Added '-X' (--exact) option
- Fixed some bugs with summaries
- Added parsing feature
- Added goto clause
- Fixed bugs with unless and equations
- Added 'eval' and 'expr' clauses
- Added 'define'
- Changed internal revision tracking to allow local RCS use
- Clarified use of -k and -f/F options and error messages

VERSION 1.33

- Changed to use POD for documentation
- Fixed UNLESS to work properly (previously untested)
- Enhanced plural sub
- Added -XL option to list extractable files
- Documented -XL &  -XT

VERSION 1.29

- Added this file (previously called CHANGES)
- Corrected LICENSE to reflect 90 day evaluation period
- Updated licensing to clarify and simplify
- Updated MANIFEST to reference PDF & Perl

VERSION 1.20

- Improved installation & instructions (-INSTALL option)
- Whitespace between error messages to enhance visibility
- Fixed manpage formatting
- Fixed -c option

POSSIBLE FUTURES:

- multiple contexts
- user settable variables
- special message fields
- speed enhancements

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
__EOF__

__README__
LOGSCAN: A Configurable Error Management Utility

Copyright 1997-2001,2008 by David C. Black. All rights reserved.

ABSTRACT:
A common problem facing most EDA tools users is how to filter through 
hundreds of lines of EDA tool output and quickly focus on the important 
information. Tools such as Synopsys Design Compiler or Quad Design Motive 
Static Timing analyzer produce messages classified as "errors", "warnings", 
or "information" in great volumes. Typically, there are simple methods to 
suppress one or more of these messages. Unfortunately, suppression often 
leads to ignoring important information. On the other hand, reading every 
line of a long report is very error prone. Some engineers choose to use 
various forms of the UNIX 'grep' utility to solve their problems; however, 
it tends to be limited to single line errors. Frequently, multi-lines of 
information are necessary to realize there is a problem and understand what 
needs fixing. Finally, some errors or lines are expected/required (e.g. 
the Thankyou message at the end of a synopsys session).

With the above framework in mind, I developed tools over the years that 
address this very issue. The remainder of the paper demonstrates a 
successful solution implemented with PERL. The script itself, 
independently developed, made available as charity-ware via the Internet
the EDA community via the HLD Wizard Web site <http://www.hldwizard.com>.

A paper with the above abstract was presented at the North America Synopsys
User's Group (SNUG) annual conference in San Jose. The paper is available
in the proceedings, on the web via SolvIt.

PAPER OUTLINE:
 1. Motivation
   a. too much output
   b. failure to check
   c. poor makefile interaction
   d. lack of context
   e. need for exception handling
 2. Example(s)
   a. errors & warnings
   b. expected & fatals
   c. overrides & ignores
 3. How it works
   a. multiple line scanning
   b. contextual output
   c. configurable error classifications
   d. exit conditions
 4. Usage
   a. manual
   b. makefiles
 5. Configuration
   a. general
   b. Synopsys specific
   c. Project specific

See INSTALLATION for notes on how to install.

LOGSCAN may be obtained as CharityWare over the web via the URL:
<http://www.hldwizard.com/logscan.tar.gz>
__EOF__
'
__INSTALLATION__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
INSTALLATION

Copyright 1997-2001,2008 by David C. Black. All rights reserved.

NOTE: LOGSCAN is a PERL 5.0 script designed for use in a UNIX 
environment; however, there is very little that is UNIX specific,
and LOGSCAN should be able to work on a PC or Macintosh running PERL
with very little modification.

Installation of LOGSCAN at its simplest involves placing the tool
in your exectuable searchpath, making certain the permissions
allow execution by users, and ensuring that PERL 5.0 or later is
installed. Common locations for the executable include /usr/local/bin,
/usr/contrib/bin, /tools/bin or possibly $HOME/bin. No special
priviledges are required by LOGSCAN.

A special -INSTALL switch (not documented elsewhere) may be used
to make LOGSCAN executable, create a symbolic link, and ensure you
have the correct readme files, and manpage available.

   logscan -INSTALL

NOTE: If PERL is not installed as 'perl', it may be necessary
to modify the first line of the LOGSCAN script. In this event, the 
PGP signature will not work on the modified copy. Alternately, you
may require users to invoke LOGSCAN with: perl logscan ARGUMENTS

A more complex installation may include setting a global LOGSCAN
environmental variable, placing the manpage in the appropriate manpage
directory, and installing one or more 'rules' files in a common
location. See the manpage (invoke with logscan -h) for more details.

You may extract some extra files with hidden option -XT as follows:

   logscan -XT filename

eXTractable files are:

   test.sh        -- a script to run tests
   test.rules     -- some rules for testing
   sample1.log    -- sample logfile
   sample2.log    -- sample logfile
   nil.rules      -- an empty ruleset
   all.rules      -- one of everything
   killer.rules   -- some rules with problems
   killer.log     -- a logfile with challenges
   synopsys.rules -- sample synopsys rules
   MANIFEST       -- the manifest
   LICENSE        -- the license
   README         -- the readme file
   INSTALLATION   -- these installation notes

LOGSCAN may be obtained as CharityWare over the web via the URL:
<http://www.hldwizard.com/logscan.tar.gz>
There is a 90 day evaluation/grace period.

Enjoy!
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
__EOF__
END OF LOGSCAN
