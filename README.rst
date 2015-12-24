===========
Resolv-conf
===========

:Status: Pre-Alpha

A ``/etc/resolv.conf`` parser crate for rust. It uses nom_ for heavy-lifting.

Why?
====

1. There is no bare file parser in the crates.io at the moment
2. I needed one to make dns resolver for rotor_

.. _rotor: http://github.com/tailhook/rotor
.. _nom: https://github.com/Geal/nom
