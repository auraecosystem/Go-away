### <a id=why></a>
# go-away

Self-hosted abuse detection and rule enforcement against low-effort mass AI scraping and bots. Uses conventional non-nuclear options.

[![Latest Release](https://img.shields.io/gitea/v/release/git/go-away?gitea_url=https%3A%2F%2Fgit.gammaspectra.live)](https://git.gammaspectra.live/git/go-away/releases)
[![Build Status](https://ci.gammaspectra.live/api/badges/git/go-away/status.svg)](https://ci.gammaspectra.live/git/go-away)
[![Go Reference](https://pkg.go.dev/badge/git.gammaspectra.live/git/go-away.svg)](https://pkg.go.dev/git.gammaspectra.live/git/go-away)

go-away sits in between your site and the Internet / upstream proxy.

Incoming requests can be selected by [rules](#rich-rule-matching) to be [actioned](https://git.gammaspectra.live/git/go-away/wiki/Rule-Actions) or [challenged](https://git.gammaspectra.live/git/go-away/wiki/Challenges) to filter suspicious requests.

The tool is designed highly flexible so the operator can minimize impact to legit users, while surgically targeting heavy endpoints or scrapers.

[Challenges](https://git.gammaspectra.live/git/go-away/wiki/Challenges) can be transparent (not shown to user, depends on backend or other logic), [non-JavaScript](#non-javascript-challenges) (challenges common browser properties), or [custom JavaScript](#custom-javascript-wasm-challenges) (from Proof of Work to fingerprinting or Captcha is supported)

See _[Why do this?](#why-do-this)_ section for the challenges and reasoning behind this tool. 

**This documentation and go-away are in active development.** See [What's left?](#what-s-left) section for a breakdown.

Check this README for a general introduction. An [in-depth Wiki](https://git.gammaspectra.live/git/go-away/wiki/) is available and being improved.

## Support

If you have some suggestion or issue, feel free to open a [New Issue](https://git.gammaspectra.live/git/go-away/issues/new) on the repository. 

[Pull Requests](https://git.gammaspectra.live/git/go-away/pulls) are encouraged and desired.

For real-time chat and other support join IRC on [#go-away](ircs://irc.libera.chat/#go-away) on Libera.Chat [[WebIRC]](https://web.libera.chat/?nick=Guest?#go-away). The channel may not be monitored at all times, feel free to ping the operators there.

## Code Mirrors

Source code is automatically pushed to the following mirrors. Packages are also mirrored on Codeberg and GitHub.

[![GammaSpectra.live](https://img.shields.io/badge/GammaSpectra.live-main+packages-green?style=flat&logo=data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+CjxzdmcgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgd2lkdGg9IjYwMCIgaGVpZ2h0PSI2MDAiIHZpZXdCb3g9Ii0zMDAgLTMwMCA2MDAgNjAwIj4KPGNpcmNsZSByPSI1MCIvPgo8cGF0aCBkPSJNNzUsMCBBIDc1LDc1IDAgMCwwIDM3LjUsLTY0Ljk1MiBMIDEyNSwtMjE2LjUwNiBBIDI1MCwyNTAgMCAwLDEgMjUwLDAgeiIgaWQ9ImJsZCIvPgo8dXNlIHhsaW5rOmhyZWY9IiNibGQiIHRyYW5zZm9ybT0icm90YXRlKDEyMCkiLz4KPHVzZSB4bGluazpocmVmPSIjYmxkIiB0cmFuc2Zvcm09InJvdGF0ZSgyNDApIi8+Cjwvc3ZnPg==&labelColor=fff)](https://git.gammaspectra.live/git/go-away) ![](https://git.gammaspectra.live/git/go-away/badges/stars.svg?style=flat) [![](https://git.gammaspectra.live/git/go-away/badges/issues/open.svg?style=flat)](https://git.gammaspectra.live/git/go-away/issues?state=open) [![](https://git.gammaspectra.live/git/go-away/badges/pulls/open.svg?style=flat)](https://git.gammaspectra.live/git/go-away/pulls?state=open)

[![Codeberg](https://img.shields.io/badge/Codeberg-mirror+packages-2185D0?style=flat&logo=codeberg&labelColor=fff)](https://codeberg.org/gone/go-away) ![](https://codeberg.org/gone/go-away/badges/stars.svg?style=flat)

[![GitHub](https://img.shields.io/badge/GitHub-mirror+packages-blue?style=flat&logo=github&labelColor=fff&logoColor=24292f)](https://github.com/WeebDataHoarder/go-away) ![](https://img.shields.io/github/stars/WeebDataHoarder/go-away?style=flat)

[![sourcehut](https://img.shields.io/badge/sourcehut-mirror-blue?style=flat&logo=sourcehut&labelColor=fff&logoColor=000)](https://git.sr.ht/~datahoarder/go-away)

Note that issues or pull requests should be issued on the [main Forge](https://git.gammaspectra.live/git/go-away).

## Installation and Setup

See the [Installation page](https://git.gammaspectra.live/git/go-away/wiki/Installation) on the Wiki for all the details.

go-away can be directly run from command line, via pre-built containers, or your own built containers.

Settings can be passed as command line options (see `go-away --help`), or in a config file passed with `--config`. See [examples/config.yml](examples/config.yml) for all config file settings. Option names differ between the two, e.g. `--cache` is `cache-path:` in the config file. When a config file is used, all other command line options are ignored, except for `--check` and `--jwt-private-key-seed`.


## Features

### Rich rule matching

[Common Expression Language (CEL)](https://cel.dev/overview/cel-overview) is used to allow arbitrary selection of client properties, not only limited to regex. Boolean operators are supported.

Templates can be defined in the Policy to allow reuse of such conditions on rule matching. Challenges can also be gated behind conditions.

See the [CEL Language Definition](https://github.com/google/cel-spec/blob/master/doc/langdef.md) for the syntax.

Rules and conditions are served with this environment:

```
remoteAddress (net.IP) - Connecting client remote address from headers or properties
  remoteAddress.network(networkName string) bool - Check whether a given IP is listed on the underlying defined network
  remoteAddress.network(networkCIDR string) bool - Check whether a given IP is listed on the CIDR
  remoteAddress.asn() int - ASN of the IP, requires a MaxMind ASN database, see ASN-based matching
  remoteAddress.country() string - ISO country code of the IP, requires a MaxMind country database, see Country-based matching
host (string) - HTTP Host
httpVersion (string) - HTTP version (eg. "HTTP/1.1")
method (string) - HTTP Method/Verb
userAgent (string) - HTTP User-Agent header
path (string) - HTTP request Path
query (map[string]string) - HTTP request Query arguments
headers (map[string]string) - HTTP request headers
fp (map[string]string) - Available fingerprints
  
Only available when TLS is enabled
   fp.ja3n (string) JA3N TLS Fingerprint
   fp.ja4 (string) JA4 TLS Fingerprint
```



### Package path

You can modify the path where challenges are served and package name, if you don't want its presence to be easily discoverable.

No source code editing or forking necessary!

Simply pass a new absolute path via the cmdline _path_ argument, like so: `--path "/.goaway_example"`, or `base-path: "/.goaway_example"` in the config file.

### Page template and customization support

Internal or external templates can be loaded to customize the look of the challenge or error page. Additionally, themes can be configured to change the look of these quickly.

These templates are included by default:

* `anubis`: An anubis-like themed challenge.
* `forgejo`: Uses the Forgejo template and assets from your own instance. Supports specifying themes like `forgejo-auto`, `forgejo-light` and `forgejo-dark`.

External templates for your site can be loaded specifying a full path to the `.gohtml` file. See [embed/templates/](embed/templates/) for examples to follow.

You can alter the language and strings in the templates directly from the [config.yml](examples/config.yml) file if specified, or add footer links directly.

Some templates support themes. Specify that either via the [config.yml](examples/config.yml) file, or via `challenge-template-theme` cmdline argument.

Most templates support overriding the logo. Specify that either via the [config.yml](examples/config.yml) file, or via `challenge-template-logo` cmdline argument.

**Feel free to make any changes to existing templates or bring your own, alter any logos or styling, it's yours to adapt!**

### Advanced actions

In addition to the common PASS / CHALLENGE / DENY / GONE rules, go-away offers more actions, plus any more extensible via code.

See the [Rule Actions page](https://git.gammaspectra.live/git/go-away/wiki/Rule-Actions) on the Wiki.

### Multiple challenge matching

Several challenges can be offered as options for rules. This allows users that have passed other challenges before to not be affected.

For example:
```yaml
  - name: standard-browser
    action: challenge
    settings:
      challenges: [http-cookie-check, preload-link, meta-refresh, resource-load, js-pow-sha256]
    conditions:
      - '($is-generic-browser)'
```

This rule has the user be checked against a backend, then attempts pass a few browser challenges.

In this case the processing would stop at `meta-refresh` due to the behavior of earlier challenges (cookie check and preload link allow failing / continue due to being silent, while meta-refresh requires displaying a challenge page).

Any of these listed challenges being passed in the past will allow the client through, including non-offered `resource-load` and `js-pow-sha256`.

### Non-Javascript challenges

Several challenges that do not require JavaScript are offered, some targeting the HTTP stack and others a general browser behavior, or consulting with a backend service.

These can be used for light checking of requests that eliminate most of the low effort scraping.

See [Transparent challenges](https://git.gammaspectra.live/git/go-away/wiki/Challenges#transparent) and [Non-JavaScript challenges](https://git.gammaspectra.live/git/go-away/wiki/Challenges#non-javascript) on the Wiki for more information.

### Custom JavaScript / WASM challenges

A WASM interface for server-side proof generation and checking is offered. We provide `js-pow-sha256` as an example of one.

You can implement Captchas or other browser fingerprinting tests within this interface.

See [Custom JavaScript challenges](https://git.gammaspectra.live/git/go-away/wiki/Challenges#custom-javascript) on the Wiki for more information.

### hCaptcha challenge

The `hcaptcha` runtime shows an [hCaptcha](https://www.hcaptcha.com/) widget on the challenge page. The solved captcha is POSTed back to go-away, checked once against the hCaptcha `siteverify` API, and a regular go-away token is issued for the challenge `duration`.

```yaml
challenges:
  hcaptcha:
    runtime: hcaptcha
    parameters:
      site-key: "your-site-key"
      # or secret: "0x..." inline
      secret-file: /run/secrets/hcaptcha-secret
      # optional
      # timeout: 10s
      # script-url: https://js.hcaptcha.com/1/api.js
      # siteverify-url: https://api.hcaptcha.com/siteverify
```

This challenge requires JavaScript, and loads third-party scripts from hCaptcha on the challenge page.

### Upstream PROXY support

Support for [HAProxy PROXY protocol](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt) can be enabled.

This allows sending the client IP without altering the connection or HTTP headers.

Supported by HAProxy, [Caddy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#proxy_protocol), [nginx](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_protocol) and others.

### Automatic TLS support and HTTP/2 support

You can enable automatic certificate generation and TLS for the site via any ACME directory, which enables HTTP/2.

Without TLS, HTTP/2 cleartext is supported, but you will need to configure the upstream proxy to send this protocol (`h2c://` on Caddy for example).

### TLS Fingerprinting

When running with TLS via autocert, TLS Fingerprinting of the incoming client is done.

This can be targeted on conditions or other application logic.

Read more about [JA3](https://medium.com/salesforce-engineering/tls-fingerprinting-with-ja3-and-ja3s-247362855967) and [JA4](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/README.md).

### Network range and automated filtering

Some specific search spiders do follow _robots.txt_ and are well behaved. However, many actors can reuse user agents, so the origin network ranges must be checked.

The samples provide example network range fetching and rules for Googlebot / Bingbot / DuckDuckBot / Kagibot / Qwantbot / Yandexbot.

Network ranges can be loaded via fetched JSON / TXT / HTML pages, or via lists. You can filter these using _jq_ or a regex.

Example for _jq_:
```yaml
  aws-cloud:
    - url: https://ip-ranges.amazonaws.com/ip-ranges.json
      jq-path: '(.prefixes[] | select(has("ip_prefix")) | .ip_prefix), (.prefixes[] | select(has("ipv6_prefix")) | .ipv6_prefix)'
```

Example for _regex_:
```yaml
  cloudflare:
    - url: https://www.cloudflare.com/ips-v4
      regex: "(?P<prefix>[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+)"
    - url: https://www.cloudflare.com/ips-v6
      regex: "(?P<prefix>[0-9a-f:]+::/[0-9]+)"
```

A regex only picks out what it matches, everything else in the content is ignored. For plain text lists, anchor it to the start of the line with `(?m)^[ \t]*`, so commented out entries like `# 10.0.0.0/8` or `// 10.0.0.0/8` are not matched as well:

```yaml
  internal:
    - file: /etc/go-away/internal-networks.txt
      regex: '(?m)^[ \t]*(?P<prefix>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+)'
```

Lists are strict: if any matched value is not a valid prefix (or ASN, for ASN lists), the whole list is rejected with a loud error naming the offending line (or jq-path output), instead of loading part of it.

#### Keeping lists up to date

By default, url lists are fetched once when the policy is loaded, and are kept until go-away is restarted or the policy is reloaded. Set `refresh` to fetch a url again periodically (minimum `5m`):

```yaml
  googlebot:
    - url: https://developers.google.com/static/search/apis/ipranges/googlebot.json
      jq-path: '(.prefixes[] | select(has("ipv4Prefix")) | .ipv4Prefix), (.prefixes[] | select(has("ipv6Prefix")) | .ipv6Prefix)'
      refresh: 6h
      refresh-jitter: 30m
```

Each refresh is randomly moved by up to ± `refresh-jitter`, so many instances started at the same time do not all hit the list host at once. It defaults to 10% of `refresh`, can be at most half of it, and `refresh-jitter: 0s` disables it.

`file` lists do not take `refresh`: they are checked for changes every minute and reloaded when modified, so they can be updated in place.

When a refresh or reload fails (the host is down, the content does not parse, ...), the previously loaded entries are kept and an error is logged. A list that fails to load at all is logged as a loud error and matches nothing.

Fetched url lists are also stored in the cache directory (`--cache`, or `cache-path:` in the config file), and rewritten after every successful refresh. On startup, a cached copy is used without fetching while it is younger than 24 hours (or than `refresh`, if shorter). An older copy is only used when fetching fails, so a restart while the list host is down still starts with the last known entries.

Downloads time out after one minute, follow up to 5 redirects (never from `https` to `http`) and are limited to 32 MiB.

### ASN-based matching

Instead of (or in addition to) static network ranges, clients can be matched by the ASN (Autonomous System Number) that announces their IP. Define named ASN groups under `asns` in the policy:

```yaml
asns:
  huawei-cloud:
  - asn: 136907
  cloudflare:
  - asn: 13335
    lookup_method: maxmind
```

These groups are used the same way as `networks` entries, e.g. `remoteAddress.network("cloudflare")` or the deprecated `inNetwork("cloudflare", remoteAddress)`.

Each entry is either a single `asn`, with an optional `comment`, or a list of ASNs loaded from a `url` or `file`:

```yaml
asns:
  datacenters:
    - url: https://raw.githubusercontent.com/X4BNet/lists_vpn/refs/heads/main/input/datacenter/ASN.txt
      regex: '(?im)^[ \t]*(?:AS)?(?P<asn>[0-9]+)[ \t]*(?:#[ \t]*(?P<comment>[^\r\n]*))?'
      refresh: 12h
      lookup_method: maxmind
    - file: /etc/go-away/extra-asns.json
      jq-path: '.[] | {asn: .number, comment: .name}'
      lookup_method: maxmind
    - asn: 136907
      comment: Huawei Cloud
      lookup_method: maxmind
```

Lists need exactly one of:

- `regex`: with an `asn` named match, and optionally a `comment` one. ASNs can be written as `13335` or `AS13335`. The example above parses lines like `AS45090 # Tencent cloud`, and being anchored to the start of the line, it skips commented out lines.
- `jq-path`: for JSON, outputting ASNs as numbers, `"AS13335"` style strings, or `{"asn": ..., "comment": ...}` objects.

As with network lists, a single invalid ASN rejects the whole list, with an error naming its line. Comments are only used in logs: with debug logging, a match logs the ASN and its comment.

Lists are only supported with `lookup_method: maxmind`, as resolving hundreds of ASNs via RADb would flood it with queries. They are kept up to date the same way as network lists, see [Keeping lists up to date](#keeping-lists-up-to-date).

Two lookup methods are available per entry:

- **RADb (default)**: pre-fetches the ASN's announced prefixes from RADb at startup/reload and matches against that static prefix list. Does not require a MaxMind database, but the prefix list is only refreshed on reload and depends on RADb availability.
- **MaxMind (`lookup_method: maxmind`)**: performs a per-request ASN lookup against a local [MaxMind GeoLite2-ASN](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) `.mmdb` database. Requires passing `--maxmind-asn-database /path/to/GeoLite2-ASN.mmdb` (or `maxmind-asn-database:` in the config file). The database file is watched and reloaded automatically on change, so it can be updated in place (e.g. by a periodic `geoipupdate` job) without restarting go-away.

A single ASN group can mix both lookup methods; a request matches if it hits either the RADb prefix list or a MaxMind entry's ASN (RADb checked first, per-request). If any entry in any group uses `lookup_method: maxmind`, a MaxMind ASN database must be configured — go-away fails to start otherwise, it does not silently skip those entries.

The CEL condition function `remoteAddress.asn() == 13335` is also available directly and always uses the MaxMind ASN database.

The old `asn:` field under a `networks` entry still works (matching this new default RADb behavior) but is deprecated in favor of the `asns` section above.

### Country-based matching

Clients can be matched by the country of their IP with the CEL condition function `remoteAddress.country()`. It returns the uppercase [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) code:

```yaml
rules:
  - name: challenge-countries
    conditions:
      - 'remoteAddress.country() in ["CN", "RU"]'
    action: challenge
    settings:
      challenges: [js-refresh]
```

This needs a local [MaxMind GeoLite2-Country or GeoLite2-City](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) `.mmdb` database, passed with `--maxmind-country-database /path/to/GeoLite2-Country.mmdb` (or `maxmind-country-database:` in the config file). It is separate from the ASN database, as GeoLite2-ASN has no country data. Like the ASN database, it is watched and reloaded automatically on change. go-away fails to start if a condition uses `country()` and no country database is configured.

The country where the IP is located is returned, falling back to the country the IP block is registered to. When the database has no country for the IP, an empty string is returned.

Take care with negated conditions such as `remoteAddress.country() != "DE"`. Localhost, private networks (`10.0.0.0/8`, `192.168.0.0/16`, `fc00::/7`, ...) and CGNAT addresses have no country, so they match too. Internal monitoring, health checks and other tools on your own network then get challenged, and most of them can't solve one. If go-away runs behind a reverse proxy without `client-ip-header` set, every request comes from the proxy's private address and every client is challenged.

Let your own networks through with a `pass` rule placed before the country rule. The `localhost` and `private` networks are defined in [examples/snippets/networks-private.yml](examples/snippets/networks-private.yml):

```yaml
rules:
  - name: allow-private-networks
    conditions:
      - 'remoteAddress.network("localhost")'
      - 'remoteAddress.network("private")'
    action: pass

  - name: challenge-foreign
    conditions:
      - 'remoteAddress.country() != "DE"'
    action: challenge
    settings:
      challenges: [js-refresh]
```

Or exclude unknown countries in the condition itself:

```yaml
    conditions:
      - 'remoteAddress.country() != "" && remoteAddress.country() != "DE"'
```

The `pass` rule is usually the better choice, as it also covers your network, ASN and other rules. Positive matches such as `remoteAddress.country() in ["CN", "RU"]` never match an empty string, so they don't need either.

### Allowing networks and ASNs

Network ranges and ASN groups can also be used to let trusted clients through. Rules are evaluated in order, so place a rule with the `pass` action before any rule that would challenge or drop them:

```yaml
networks:
  office:
    - prefixes: ["203.0.113.0/24", "2001:db8::/32"]

asns:
  trusted-isp:
    - asn: 3320
      comment: Deutsche Telekom
      lookup_method: maxmind

rules:
  - name: allow-trusted
    conditions:
      - 'remoteAddress.network("office")'
      - 'remoteAddress.network("trusted-isp")'
    action: pass
```


### Multiple backend support

Multiple backends are supported, and rules specific on backend can be defined, and conditions and rules can match this as well.

Subdomain wildcards like `*.example.com`, or full fallback wildcard `*` are supported.

This allows one instance to run multiple domains or subdomains.

### IPv6 Happy Eyeballs challenge retry

In case a client connects over IPv4 first then IPv6 due to [Fast Fallback / Happy Eyeballs](https://en.wikipedia.org/wiki/Happy_Eyeballs), the challenge will automatically be retried.

This is tracked by tagging challenges with a readable flag indicating the type of address.

## Example policies

### Forgejo

The policy file at [examples/forgejo.yml](examples/forgejo.yml) provides a ready template to be used on your own Forgejo instance.

Important notes:
* Edit the `http-cookie-check` challenge, as this will fetch the listed backend with the given session cookie to check for user login.
* Adjust the desired blocked networks or others. A template list of network ranges is provided, feel free to remove these if not needed.
* Check the conditions and base rules to change your challenges offered and other ordering.
* By default Googlebot / Bingbot / DuckDuckBot / Kagibot / Qwantbot / Yandexbot are allowed by useragent and network ranges.

### Generic

The policy file at [examples/generic.yml](examples/generic.yml) provides a baseline to place on any site, that can be modified to fit your needs.

Important notes:
* Edit the `homesite` rule, as it's targeted to pages you always want to have available, like landing pages.
* Edit the `is-static-asset` condition or the `allow-static-resources` rule to allow static file access as necessary.
* If you have an API, add a PASS rule targeting it.
* Check the conditions and base rules to change your challenges offered and other ordering.
* Add or modify rules to target specific pages on your site as desired.
* By default Googlebot / Bingbot / DuckDuckBot / Kagibot / Qwantbot / Yandexbot are allowed by useragent and network ranges.

### Snippets

You can define snippets to be included. YAML anchors/aliases are supported.

Pass a snippets folder with `--policy-snippets` (can be given multiple times), or list them under `policy-snippets:` in the config file.

See [examples/snippets/](examples/snippets/) for some defaults including indexer bots, challenges and other general matches.



## Why do this?
In the past few years this small git instance has been hit by waves and waves of scraping.
This was usually fought back by random useragent blocks for bots that did not follow [robots.txt](/robots.txt), until the past half year, where low-effort mass scraping was used more prominently.

Recently these networks go from using residential IP blocks to sending requests at several hundred requests per second.

If the server gets sluggish, more requests pile up. Even when denied they scrape for weeks later. Effectively spray and pray scraping, process later.

At some point about 300Mbit/s of incoming requests (not including the responses) was hitting the server. And all of them nonsense URLs, or hitting archive/bundle downloads per commit.

**If AI is so smart, why not just git clone the repositories?**

* Wikimedia has posted about [How crawlers impact the operations of the Wikimedia projects](https://diff.wikimedia.org/2025/04/01/how-crawlers-impact-the-operations-of-the-wikimedia-projects/) [01/04/2025]

* Xe (Anubis creator) has written about similar frustrations in several blogposts:
  * [Amazon's AI crawler is making my git server unstable](https://xeiaso.net/notes/2025/amazon-crawler/) [01/17/2025]
  * [Anubis works](https://xeiaso.net/notes/2025/anubis-works/) [04/12/2025]

* Drew DeVault (sourcehut) has posted several articles and outages regarding the same issues:
  * [Drew Blog: Please stop externalizing your costs directly into my face](https://drewdevault.com/2025/03/17/2025-03-17-Stop-externalizing-your-costs-on-me.html) [17/03/2025]
    * (fun tidbit: I'm the one quoted as having the feedback discussion interrupted to deal with bots!)
   * [sourcehut status: LLM crawlers continue to DDoS SourceHut](https://status.sr.ht/issues/2025-03-17-git.sr.ht-llms/) [17/03/2025]
  * [sourcehut Blog: You cannot have our user's data](https://sourcehut.org/blog/2025-04-15-you-cannot-have-our-users-data/) [15/04/2025]

* Others were also suffering at the same time [[1]](https://donotsta.re/notice/AreSNZlRlJv73AW7tI) [[2]](https://community.ipfire.org/t/suricata-ruleset-to-prevent-ai-scraping/11974) [[3]](https://gabrielsimmer.com/blog/stop-scraping-git-forge) [[4]](https://gabrielsimmer.com/blog/stop-scraping-git-forge) [[5]](https://blog.nytsoi.net/2025/03/01/obliterated-by-ai).

---
Initially I deployed Anubis, and yeah, it does work!

This tool started as a way to replace [Anubis](https://anubis.techaro.lol/) as it was not found as featureful as desired, and the impact was too high.

go-away may not be as straight to configure as Anubis but this was chosen to reduce impact on legitimate users, and offers many more options to dynamically target new waves.

### Can't scrapers adapt?

Yes, they can. At the moment their spray-and-pray approach is cheap for them.

If they have to start adding an active browser in their scraping, that makes their collection expensive and slow.

This would more or less eliminate the high rate low effort passive scraping and replace it with an active model.

go-away offers a highly configurable set of challenges and rules that you can adapt to new ways.

## What's left?

go-away has most of the desired features from the original checklist that was made in its development. 
However, a few points are left before go-away can be called v1.0.0:

* [x] Several parts of the code are going through a refactor, which won't impact end users or operators.
* [ ] Documentation is lacking and a more extensive one with inline example is in the works.
* [x] Policy file syntax is going to stay mostly unchanged, except in the challenges definition section.
* [ ] Allow end users to pick fallback challenges if any fail, specially with custom ones.
* [ ] Replace Anubis-like default template with own one.
* [x] Define strings and multi-language support for quick modification by operators without custom templates.
* [ ] Have highly tested paths that match examples.
* [x] Caching of temporary fetches, for example, network ranges.
* [x] Allow live and dynamic policy reloading.
* [x] Multiple domains / subdomains -> one backend handling, CEL rules for backends
* [ ] Merge all rules and conditions into one large AST for higher performance.
* [ ] Explore exposing a module for direct Caddy usage.
* [x] More defined way of picking HTTP/HTTP(s) listeners and certificates.
* [x] Expose metrics for challenge solve rates and acting on them.
  * [ ] Metrics for common network ranges / AS / useragent



## Other Similar Projects

|                                         Project                                          |                                                                                                                                                      Source Code                                                                                                                                                      | Description                                                                                                                | Method                                       |
|:----------------------------------------------------------------------------------------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:---------------------------------------------------------------------------------------------------------------------------|:---------------------------------------------|
|                          [Anubis](https://anubis.techaro.lol/)                           |                                       [![GitHub](https://img.shields.io/badge/GitHub-TecharoHQ/anubis-blue?style=flat&logo=github&labelColor=fff&logoColor=24292f)](https://github.com/TecharoHQ/anubis)<br/>Go / [MIT](https://github.com/TecharoHQ/anubis/blob/main/LICENSE)                                        | Proxy that uses JavaScript proof of work to weight request based on simple match rules                                     | JavaScript PoW (SHA-256)                     |
|             [powxy](https://forge.lindenii.runxiyu.org/powxy/-/repos/powxy/)             |                  [![lindenii.runxiyu.org](https://img.shields.io/badge/lindenii-powxy-blue?style=flat&logo=git&labelColor=fff&logoColor=000)](https://forge.lindenii.runxiyu.org/powxy/-/repos/powxy/)<br/> Go / [BSD 2-Clause](https://forge.lindenii.runxiyu.org/powxy/-/repos/powxy/tree/LICENSE)                  | Powxy is a reverse proxy that protects your upstream service by challenging clients with proof-of-work.                    | JavaScript PoW (SHA-256) with manual program |
|      [PoW! Bot Deterrent](https://git.sequentialread.com/forest/pow-bot-deterrent)       | [![SequentialRead](https://img.shields.io/badge/SequentialRead-forest/pow--bot--deterrent-blue?style=flat&logo=gitea&labelColor=fff&logoColor=000)](https://git.sequentialread.com/forest/pow-bot-deterrent)<br/> Go / [GPL v3.0](https://git.sequentialread.com/forest/pow-bot-deterrent/src/branch/main/LICENSE.md) | A proof-of-work based bot deterrent. Lightweight, self-hosted and copyleft licensed.                                       | JavaScript PoW (WASM scrypt)                 |
|                        [CSSWAF](https://github.com/yzqzss/csswaf)                        |                                            [![GitHub](https://img.shields.io/badge/GitHub-yzqzss/csswaf-blue?style=flat&logo=github&labelColor=fff&logoColor=24292f)](https://github.com/yzqzss/csswaf)<br/>Go / [MIT](https://github.com/yzqzss/csswaf/blob/main/LICENSE)                                            | A CSS-based NoJS Anti-BOT WAF (Proof of Concept)                                                                           | Non-JS CSS Subresource loading order         |
|                 [anticrawl](https://flak.tedunangst.com/post/anticrawl)                  |                                                        [![humungus.tedunangst.com](https://img.shields.io/badge/tedunangst-anticrawl-blue?style=flat&logo=mercurial&labelColor=fff&logoColor=000)](https://humungus.tedunangst.com/r/anticrawl)<br/>Go / None                                                         | Go http handler / proxy for regex based rules                                                                              | Non-JS manual Challenge/Response             |
| [ngx_http_js_challenge_module](https://github.com/simon987/ngx_http_js_challenge_module) |     [![GitHub](https://img.shields.io/badge/GitHub-simon987/ngx_http_js_challenge_module-blue?style=flat&logo=github&labelColor=fff&logoColor=24292f)](https://github.com/simon987/ngx_http_js_challenge_module)<br/>C / [GPL v3.0](https://github.com/simon987/ngx_http_js_challenge_module/blob/master/LICENSE)     | Simple javascript proof-of-work based access for Nginx with virtually no overhead.                                         | JavaScript Challenge                         |
|           [haproxy-protection](https://gitgud.io/fatchan/haproxy-protection/)            |                  [![GitGud](https://img.shields.io/badge/GitGud-fatchan/haproxy--protection-blue?style=flat&logo=gitlab&labelColor=fff&logoColor=000)](https://gitgud.io/fatchan/haproxy-protection/)<br/> Lua / [GPL v3.0](https://gitgud.io/fatchan/haproxy-protection/-/blob/master/LICENSE.txt)                   | HAProxy configuration and lua scripts allowing a challenge-response page where users solve a captcha and/or proof-of-work. | JavaScript Challenge / Captcha               |

## Development

This Go package can be used as a command on `git.gammaspectra.live/git/go-away/cmd/go-away` or a library under `git.gammaspectra.live/git/go-away/lib`

### Running tests

Run the full test suite from the repository root:

```sh
go test ./...
```

To run tests for a specific package:

```sh
go test git.gammaspectra.live/git/go-away/lib
go test git.gammaspectra.live/git/go-away/lib/policy
go test git.gammaspectra.live/git/go-away/utils
```




