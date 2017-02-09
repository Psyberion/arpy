Disclaimer
==========

This piece of software is build for educationar reasons. Using this tool on
networks that you do not own or do not have permission to use it on is illegal.
I do not take any responsibility for the use of this program.

Dependencies
============

Scapy_
------

Installing ``scapy`` can be done like this:

.. code::

    $ wget scapy.net
    $ unzip index.html
    $ cd scapy*
    # python setup.py install

Arping_
-------

Installing ``arping`` is as easy as:

.. code::

    # apt-get install arping

TCPDump_
--------

``tcpdump`` can be installed via your packet manager:

.. code::

    # apt-get install tcpdump


Example
=======

The following is an example use of ARpy, from start to finish.

First, scan the network for potential targets, as follows:

.. code::

    # ./ar.py --list --interface <INTERFACE>

``<INTERFACE>`` is exchanged for the interface you want to use, e.g. ``eth0``.

This will list all hosts on the network. Once you've chosen which host to target
(and determined the gateway (ar.py does not do this for you), run the following:

.. code::

	# ./ar.py -t <TARGET IP> -r <GATEWAY IP> -i <INTERFACE>

``<TARGET IP>`` is exchanged for the target IP, e.g. ``192.168.0.2`` and
``<GATEWAY IP>`` is exchanged for the router IP, e.g. ``192.168.0.1``.

This will start the ARP poisoning attack and the network sniffing. Once you're
done sniffing the network, just hit ``CTRL+C`` to quit.

.. _Scapy : http://www.secdev.org/projects/scapy/doc/installation.html
.. _Arping : https://github.com/ThomasHabets/arping
.. _TCPDump : http://www.tcpdump.org/
