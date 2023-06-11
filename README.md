
<p align="center">
<img alt="safepasswords logo" title="Safe Passwords--an attempt to make it safer to manage passwords in memory."
src="https://snapwebsites.org/sites/snapwebsites.org/files/images/safepasswords-logo.png" width="230" height="230"/>
</p>

# Introduction

The Safe Passwords library is here to make it simpler to manage passwords
in memory in a safe manner. In most cases, having passwords linger in your
memory is dangerous as someone can eventually get a hold of them.

This library offers a way to clear the passwords once not necessary anymore.
This happens at the time you destroy the `safepasswords::string` object.


# Implementation

## Safety First

In order to make a memory based password as safe as possible, we want to:

* try to clear all the buffers that included a password in clear
* avoid having the memory holding the password swapped out to disk
* avoid any intermediate buffers if at all possible (directly work with
  the safepasswords::string instead of std::string)

## Large Buffers

To prevent Linux from sending data to disk (i.e. when the OS decides to
swap out some buffers to disk), the mark our buffers as non-swappable
which is done with mlock(3). This functionality requires the buffers
to be aligned to a memory page. To do so, we allocate exactly a string
buffer of exactly one page. This means all the safepasswords strings
are at least 4Kb in size (plus the string and buffer structures).

We want to enhance this by implementing a memory allocation within such
buffers (i.e. allocate 16Kb and then allocate the string buffers within
that 16Kb of RAM instead of allocating 4K per string).


# Tools

## Generate Password

The `generate-password` tool can be used to see the list of available
digests or generate passwords from your command line.


# License

The source is covered by the GPL 3 license.


# Bugs

Submit bug reports and patches on
[github](https://github.com/m2osw/safepasswords/issues).


_This file is part of the [snapcpp project](https://snapwebsites.org/)._
