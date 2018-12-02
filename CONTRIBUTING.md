# How to contribute

## Q/A

#### Did you find a bug?

  * **Ensure the bug was not already reported** by searching on GitHub under [Issues](https://github.com/sineang01/hashkitcxx/issues).
  * If you're unable to find an open issue addressing the problem, [open a new one](https://github.com/sineang01/hashkitcxx/issues/new). Be sure to include a **title and clear description**, as much relevant information as possible, and a **code sample** or an **executable test case** demonstrating the expected behavior that is not occurring.

#### Did you write a patch that fixes a bug?

  * Open a new GitHub pull request with the patch.
  * Ensure the PR description clearly describes the problem and solution. Include the relevant issue number if applicable.
  * Before submitting, please read the the rest of this guide to know more about coding conventions and benchmarks.

#### Did you fix whitespace, format code, or make a purely cosmetic patch?

  * Changes that are cosmetic in nature and do not add anything substantial to the stability, functionality, or testability of HashKitCXX will generally not be accepted.

#### Do you intend to add a new feature or change an existing one?

  * Suggest your change opening a [new issue](https://github.com/sineang01/hashkitcxx/issues/new) and start writing code.
  * If the feedback is positive, make a pull request when your code is complete.

## Testing

Unit tests are built using [Boost.Test](https://www.boost.org/doc/libs/1_60_0/libs/test/doc/html/index.html) library. Refer to the Boost documentation for its use.
When at all possible, patches should include tests. These can either be added to an existing test, or completely new.

## Submitting changes

Please send a [GitHub Pull Request](https://github.com/sineang01/hashkitcxx/pull/new/master) with a clear list of what you've done (read more about [pull requests](http://help.github.com/pull-requests/)). When you send a pull request, please include unit tests and examples, unless not applicable. We can always use more test coverage. Please follow our coding conventions (below) and make sure all of your commits are atomic (one feature per commit).

Always write a clear log message for your commits. One-line messages are fine for small changes, but bigger changes should look like this:

    $ git commit -m "A brief summary of the commit
    > 
    > A paragraph describing what changed and its impact."

If you are used to prefixes in your commit messages, you can use the following:
  * `!U` (update)
  * `!B` (bugfix)
  * `!D` (delete)
  * `!A` (addition)

Using prefixes in git commits is not mandatory anyway.

## Coding conventions

This is an hash library, sometimes the code might not be as readable as we would like, but we optimize for speed. However, we try to make our code readable whenever we can.
Here some coding conventions:

  * Use underscore as word separator.
  * Everything is lowercase: this applies to class/struct names, members, methods, any other variables (including statics, consts or constexprs), namespaces and generally everything else (e.g. `out_of_range`).
  * Macros/Defines are written using only uppercase letters and underscores (e.g. `HASHLIBCXX_USE_STRING`).
  * Template times are prefixed with a capital T and follow camelcase syntax with first letter uppercase (e.g. `THash`).
  * Comments are whenever possible lowercase too; exceptions are allowed (one of which is the copyright comment block).
  * All variables in a class are prefixes with `m_` except static variables, those are prefixed with `s_`.
  * Use `#pragma once` instead of the define guard.
  * Do not use C-style cast.
  * Use `constexpr` whenever it is possible to evaluate the value of the function or variable at compile time.
  * If the function doesn't throw, define it `noexcept`.
  * Initialize variables and objects using C++11 uniform initialization, except `auto`.
  * Do not use macros/defines in header files.
  
## Formatting

Formatting is done using **Clang-format** and **Clang-tidy**, version 7.0.0. Please use the **same version** because other versions might format code slightly differently.
Configuration files are provided in the repository to configure those systems with the appropriate settings, use them while coding your patch or new feature.

Thanks!
