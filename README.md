# LOGSCAN: A Configurable Error Management Utility

Copyright 1997-2001,2008,2013 by David C. Black. All rights reserved.

## ABSTRACT:

A common problem facing most EDA tools users is how to filter through 
thousands of lines of EDA tool output and quickly focus on the important 
information. Tools such as __Synopsys Design Compiler__ or __Quad Design Motive
Static Timing Analyzer__ produce messages classified as **errors**, **warnings**, 
or **information** in great volumes. Typically, there are simple methods to 
suppress one or more of these messages. Unfortunately, suppression often 
leads to ignoring important information. On the other hand, reading every 
line of a long report is very error prone. Some engineers choose to use 
various forms of the UNIX `grep` utility to solve their problems; however, 
it tends to be limited to single line errors. Frequently, multi-lines of 
information are necessary to realize there is a problem and understand what 
needs fixing. Finally, some errors or lines are expected/required (e.g. 
the _Thankyou_ message at the end of a synopsys session).

With the above framework in mind, I developed tools over the years that 
address this very issue. The remainder of the paper demonstrates a 
successful solution implemented with PERL. The script itself, 
independently developed, made available as charity-ware via the Internet
the EDA community via the GiHub site <https://github.com>.

A paper with the above abstract was presented at the _North America Synopsys
User's Group_ (**SNUG**) annual conference in San Jose in 1998. The paper is
available in the proceedings, on the web via Synopsys SolvIt.

## PAPER OUTLINE

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
<https://github.com/dcblack/logscan/archive/master.zip>
