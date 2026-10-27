# API response fixtures

These JSON bodies were written by hand from each vendor's public REST
API reference. They were **not** recorded from a live Sentinel, Splunk
or SecOps instance, because none is available to this project.

What the adapter tests built on them prove: the adapters send the
requests we intended (method, URL, body, auth header) and handle the
response shapes as documented. What they do not prove: that a real
API accepts these requests. Replace a fixture with a recorded,
secret-scrubbed response the first time a live call is made, and note
it in BUILD_LOG.md.
