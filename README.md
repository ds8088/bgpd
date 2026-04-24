# bgpd

A BGP daemon that fetches IPv4/IPv6 prefixes for a list of ASNs from the [ipverse/as-ip-blocks](https://github.com/ipverse/as-ip-blocks) repository, summarizes them and advertises the resulting prefixes over BGP.

## Purpose

My home ISP has direct peering with a specific AS, which, in theory, should be the fastest way to reach that AS.

However, for some reason, that ISP decides to route the traffic through a very suboptimal path, ignoring the peering; this introduces a fairly good amount of latency, which is undesirable in my case.

To overcome this problem, I have come up with a somewhat complex but robust solution:

- `bgpd` (this tool) is used to periodically fetch a list of IPv4/IPv6 prefixes that the problematic AS announces;
- the prefixes are further summarized to reduce the computational overhead;
- in the `bgpd` configuration, `next_hop_ipv{4,6}` options point to a gateway that is hosted by another ISP, which does not suffer from this routing problem;
- my home router sets up BGP peering with `bgpd`, picks up the summarized routes and inserts them into its RIB, guaranteeing that any home devices will route the traffic to an alternative gateway, thus avoiding the suboptimal path.

## Usage

1. Download the [latest release](https://github.com/ds8088/bgpd/releases/latest);
2. Make a copy of `config.example.json` and save it as `config.json`;
3. Open `config.json` and add your desired AS numbers;
4. Replace `next_hop_ipv4` and `next_hop_ipv6` according to your gateway address;
5. Start bgpd.

## Docker image

A Docker image is available in GHCR.

To run the container, you should mount the directory that contains your
config.json to the container's /data.
The entire directory should be mounted so that the tool can persist cookies across restarts:

```sh
docker run -v ~/bgpd:/data ghcr.io/ds8088/bgpd:latest
```

## Building from source

[Zig](https://ziglang.org/) 0.15.1+ is required in order to build from source.

Building:

```sh
zig build -Drelease=true
```

To check if all tests are passing, use:

```sh
zig build test --summary all
```
