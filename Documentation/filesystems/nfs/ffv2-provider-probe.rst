===================================
NFSD Flex Files v2 provider probe
===================================

The D0.5 probe is compiled into nfsd.  It identifies the common nfsd
validation boundary at which a future Flex Files v2 (FFv2) provider could be
called.  It is not a provider API and does not make a provider callback
reachable.

Wire operation boundary
=======================

The probe recognizes operation values 78 through 91.  Values 92 and above
are outside this probe and fail the normal NFS operation range check.  The
operation tables contain complete decoders and status-only encoders for these
14 values.

``CHUNK_READ`` and ``CHUNK_HEADER_READ`` retain their complete, bounded
arguments in ``struct nfsd4_chunk_read`` and
``struct nfsd4_chunk_header_read``.  They are the only operations allowed to
reach the probe boundary.  Their arguments contain no allocated storage and
therefore need no operation release function.

The other 12 operations remain bound to ``nfsd4_ffv2_notsupp()``.  Several of
their decoders consume fields only to validate and advance the XDR stream.
They must not be redirected to a provider until every callback input has
bounded owned storage and a matching release path.  Mutating operations also
need provider-generation idempotency before they can be dispatched.

Validation path
===============

A mapped read follows this path::

  nfsd4_decode_compound()
    -> nfsd4_dec_ops[OP_CHUNK_*]()
  nfsd4_proc_compound()
    -> nfsd4_sequence() and the normal session-slot replay path
    -> nfsd4_putfh()
      -> nfsd_ffv2_fh_map()
        -> nfsd_ffv2_fh_parse()
        -> nfsd_ffv2_binding_admit()
        -> fh_verify_ffv2_mapped()
        -> export, object, generation, and dentry identity validation
    -> current-filehandle and migrated-filesystem checks
    -> nfsd4_ffv2_export_policy_check()
    -> nfsd4_ffv2_probe()
      -> check_nfsd_access()
      -> nfsd_ffv2_provider_probe()
        -> active mapped-binding revalidation
        -> NFS4ERR_NOTSUPP
  nfsd4_encode_operation()
  nfsd4_release_compoundargs()
    -> fh_put()
      -> nfsd_ffv2_binding_put()
        -> nfsd_ffv2_complete()

The binding acquired by ``PUTFH`` pins the provider generation and is copied
or released with the normal ``svc_fh`` ownership rules.  Unregister and netns
teardown remove admission before waiting for that binding admission to drain.
The probe performs no asynchronous work and retains no request, compound,
XDR, credential, or reply pointer.

Closed provider gate
====================

The probe returns ``NFS4ERR_NOTSUPP`` after mapped identity and export access
validation because three nfsd-core contracts are not implemented yet:

* a kernel-owned binding between the authenticated NFSv4.1 MDS session and
  the registered service generation;
* a trusted FFv2 stateid registry with stale, revoked, and old-incarnation
  validation; and
* a content digest in the session replay record, including defined uncached
  and lost-reply behavior.

``nfsd_ffv2_register()`` therefore remains ``-EOPNOTSUPP``.  All provider
callbacks remain unreachable.  With ``CONFIG_NFSD_FFV2_LIVE_TEST``, the
``ffv2-provider-probe`` debugfs file reports attempts that reached the
fail-closed boundary; it is evidence instrumentation, not an enable switch.
