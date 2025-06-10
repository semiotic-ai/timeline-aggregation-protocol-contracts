# Timeline Aggregation Protocol (TAP) Contract(s)

[![npm version](https://badge.fury.io/js/@semiotic-labs%2Ftap-contracts-bindings.svg)](https://badge.fury.io/js/@semiotic-labs%2Ftap-contracts-bindings)
[![npm downloads](https://img.shields.io/npm/dm/@semiotic-labs/tap-contracts-bindings.svg)](https://www.npmjs.com/package/@semiotic-labs/tap-contracts-bindings)
[![License](https://img.shields.io/npm/l/@semiotic-labs/tap-contracts-bindings.svg)](https://www.npmjs.com/package/@semiotic-labs/tap-contracts-bindings)
[![Dependencies](https://img.shields.io/librariesio/release/npm/@semiotic-labs/tap-contracts-bindings)](https://www.npmjs.com/package/@semiotic-labs/tap-contracts-bindings)

## Create types and bindings

First, start [forge](https://book.getfoundry.sh/getting-started/installation). If you don't already have it installed, make sure you restart your shell.

```terminal
foundryup
```

Next, build the smart contracts.

```terminal
yarn build
```

Afterwards, enter the bindings directory:

```terminal
cd bindings
```

And run the following commands to generate the types and bindings:

```terminal
yarn bindings
yarn tsc
```

With the bindings generated, you may publish to npm using the following command:

```terminal
npm publish
```

You must have the relevant access permissions to publish this crate.
You can check these by seeing whether `tap-contracts-bindings` is listed as `read-write` under

```terminal
npm access list packages
```
