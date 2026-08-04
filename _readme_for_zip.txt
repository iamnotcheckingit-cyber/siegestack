==================================================================
  WHAT RAM IS IN THIS PC?
  from siegestack.com/jesse
==================================================================

Hey kiddo.

You've got an empty RAM slot and we need to know exactly what
stick to buy to fill it. This little script asks Windows what's
already installed and prints the answer.


WHAT TO DO
------------------------------------------------------------------

1. Double-click  ram-report.bat

2. Windows may say "Windows protected your PC" with a blue box.
   That's just because the file came from the internet, not
   because anything is wrong. Click  More info  ->  Run anyway

3. A black window opens and prints the answer.

4. It also saves a file called  ram-report.txt  on your Desktop.
   Send me that file and I'll order the right stick.

That's it. Takes about five seconds.


WHAT IT DOES AND DOESN'T DO
------------------------------------------------------------------

It only READS information Windows already has about your memory.

  - It does not install anything
  - It does not change anything
  - It does not connect to the internet at all
  - It does not need administrator rights

You can read the whole thing yourself before running it. Open
ram-report.bat in Notepad (right-click -> Open with -> Notepad)
and every single line is there in plain English. I'd rather you
got in the habit of checking that on anything you download,
including from me.


IF IT DOESN'T WORK
------------------------------------------------------------------

Option A - right-click ram-report.bat, choose
  "Run as administrator", and try again.

Option B - use the copy-paste command on siegestack.com/jesse
  instead. Nothing to download at all, it just runs in a
  PowerShell window.

Option C - download CPU-Z (free, from cpuid.com), open the SPD
  tab, and click through each slot. It shows the same thing in a
  nicer window, including the names of the empty slots.

Option D - paste this into ChatGPT, Claude, Copilot or Gemini,
  then paste whatever the script printed underneath it:

  ----------------------------------------------------------------
  I want to add one more stick of RAM to my desktop PC to fill an
  empty slot. Below is a report of the memory currently installed
  and my motherboard model. Please tell me: (1) the exact
  specification of the stick I should buy, (2) whether mixing it
  with what I already have is risky and why, (3) which physical
  slot it should go in for dual channel, and (4) what to check in
  the BIOS afterwards. Here is the report:
  ----------------------------------------------------------------

Option E - just call me. Genuinely, that's fine. This is what I
  do all day.


ONE THING WORTH KNOWING
------------------------------------------------------------------

DDR5 is picky about mixing sticks. Two sticks that weren't sold
together as a matched pair can refuse to run at full speed, or
stop the PC booting until XMP/EXPO gets switched off in the BIOS.

So the safest buy is the identical part number to what's already
in there - which is exactly what the script tells you.

Also: on most boards, if you're running two sticks they should go
in slots A2 and B2 (the 2nd and 4th from the CPU), not A1 and B1.
Sounds wrong. Isn't. Check your motherboard manual - the script
prints your motherboard model at the top.


------------------------------------------------------------------

Love you, kiddo. See you soon.

                                                          - Dad

------------------------------------------------------------------
