# Internals

This documents bits and pieces of how Cycle works internally, and the logic/reasoning behind the code.

## Reading from Reaver

I thought that parsing text from all tools was equally easy. I was wrong. One has to take into account all sorts of small details, which have a combinatory effect and get complicated very quickly.

One such detail is how Reaver outputs text on the command line. I may have done this the long way around, but Cycle interprets Reaver output by creating its own [state machine](https://en.wikipedia.org/wiki/Finite-state_machine) of sorts. It needs to understand (a subset of) the possible output that Reaver may print at any time, and then scan lines to match that output.

It does so by using [pexpect](https://pexpect.readthedocs.io/en/stable/) (while it uses `Popen` from [subprocess](https://docs.python.org/3/library/subprocess.html) for managing other processes such as `mdk4`) to ease issues concerning sending input to interactive confirmation prompts to `reaver`, and for convenience functions for `expect`ing output.

### The State Machine

To ease my (and others') understanding of Reaver's output and how Cycle is intended to function (since I'm yet to implement functionality following this diagram), I used [PlantUML](https://plantuml.com) to create the diagram below showing the output that Reaver will print given in scenarios that Cycle is concerned about. Reaver may well print far more than this, but this should establish a reasonable baseline.

![Reaver activity diagram](uml/reaver.svg)