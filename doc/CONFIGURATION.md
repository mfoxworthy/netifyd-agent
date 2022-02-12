Netify Agent Configuration
==========================

Domain Transforms
-----------------

The Agent supports "domain transforms" (known generally as key transforms).  A few points to consider:
- Domain transforms can only be defined in the new applications configuration file format (xfm entries).
- ... are extended regular expressions that operate on the search key (a domain).
- ... should be used sparingly; only when necessary as they are fairly expensive.
- ... support sub-pattern search with replace:
  * `$n` - n-th backreference (i.e., a copy of the `n`-th matched group specified with parentheses in the regex pattern).  `n` must be an integer value designating a valid backreference, greater than 0, and of two digits at most.
  * `$&` - A copy of the entire match
  * ``$\`` - The prefix (i.e., the part of the target sequence that precedes the match).
  * `$´` - The suffix (i.e., the part of the target sequence that follows the match).
  * `$$` - A single `$` character.

Example
-------
```xfm:^instagram\.[0-9a-z\.-]+\.fbcdn\.[a-z]+$:instagram.com```

The above transform would replace an input domain such as "`instagram.fyvr1-1.fna.fbcdn.net`" to "`instagram.com`" which would match a domain entry for "`instagram.com`" in the apps list.
