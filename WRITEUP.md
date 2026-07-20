# Write-up: Building the Web Recon Automation Framework

## What was hardest to build

**Making failure a first-class citizen instead of an afterthought.**

The obvious way to write this tool is eight `try/except` blocks scattered
through one long script, each printing "skipping..." and moving on. That
works until you need to generate a report from the results, and now you're
checking `if whois_data is not None and whois_data != {}` in five different
places with five slightly different bugs.

The actual hard part was deciding on one shape for "a module ran" *before*
writing any of the modules: every module returns
`{status, module, data, error}`, full stop, whether it succeeded or not.
The `safe_run()` decorator in `modules/utils.py` enforces that shape at the
boundary so no individual module has to think about it — `whois_lookup.py`
just raises on failure like a normal function would, and the wrapper
converts that into structured data. Once that boundary existed, the report
generator got to be dumb: every section checks `result["status"] == "ok"`
and falls back to a one-liner otherwise. I didn't design it that way on the
first pass — I started with per-module try/except and only pulled the
pattern out into `utils.py` after I noticed I was writing the same
try/except shape six times.

The second hardest part was the SSL/TLS module, for a boring reason: Python
gives you `ssock.getpeercert()` as a dict, but the subject and issuer come
back as a tuple of single-item tuples of key/value pairs — not a dict — so
you have to flatten it yourself, and the date format
(`'Jul 11 00:03:50 2026 GMT'`) needs an exact `strptime` format string or it
silently fails on some certs. Small thing, easy to get wrong, and it's the
kind of bug that only shows up on certain CAs' certificate formatting.

**Testing this against a real target inside a sandboxed environment** also
forced a design decision I wouldn't have made otherwise: I ran the tool
against a live domain during development and two modules (WHOIS, IP
geolocation) got blocked by the sandbox's own network egress rules. That
was actually useful — it was a free integration test of the failure-boundary
design under real conditions, not just simulated exceptions. The scan still
finished and the report still generated, with both sections correctly
marked as unavailable instead of the whole run dying. If I'd only tested
with `assert` statements and manually raised exceptions, I wouldn't have
caught the specific way `requests` and the WHOIS library actually fail
(connection timeout vs. HTTP 403 vs. socket refusal all needed different
handling in practice, not just "except Exception").

## What I learned about recon while building it

**Passive recon is noisier and less "free" than it sounds.** The instinct
is to treat WHOIS/DNS/headers as trivially available public data, but in
practice: WHOIS increasingly returns redacted registrant info post-GDPR,
some registries rate-limit or block WHOIS queries outright, and free
IP-geolocation APIs will 403 you if you're coming from a flagged IP range
or hitting their endpoint from automated tooling. None of that is a bug in
the recon tool — it's the actual texture of doing this against real
infrastructure, and a report that just crashes on the first blocked lookup
gives a false impression that recon is easy right up until it silently
fails on the one target where it mattered.

**Security header adoption is inconsistent even among large targets.**
Building the checklist in `security_analysis.py` meant deciding which six
headers actually matter (CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy) and I expected most major sites to
have all six. In practice it's common to see strong CSP/HSTS but a missing
Permissions-Policy, which is a good reminder that "has security headers"
isn't binary — a coverage percentage is a more honest signal than a
pass/fail, which is why the report scores it instead of flagging it green
or red.

**robots.txt is a better recon source than its reputation suggests.** It's
often dismissed as "just tells crawlers what to skip," but the Disallow
list is frequently a map of exactly the paths an organization didn't want
indexed — staging routes, internal tooling, admin panels — and it's
completely unauthenticated to read. Parsing it revealed that some sites
declare the same Disallow path multiple times across different `User-agent`
blocks, which meant the parser needed to decide whether to dedupe or show
it as-is (I chose to preserve what's actually in the file rather than
"clean it up," since for a recon report the raw declared structure is more
informative than a tidied version).

**The gap between "runs once on my machine" and "won't crash on someone
else's target" is where most of the actual engineering effort goes.**
The data-collection logic per module is genuinely simple — a WHOIS call, a
DNS resolve, a GET request. The thing that took real design work was
everything around that: normalizing whatever a user types as a target,
isolating failures so one blocked module doesn't sink the scan, and turning
inconsistent partial data into a report that reads as intentional rather
than broken. That's the part that doesn't show up if you just skim the
individual module files.
