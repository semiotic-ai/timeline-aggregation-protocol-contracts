# Timeline Aggregation Protocol (TAP) Contract(s)

## Create types and bindings

First, start [forge](https://book.getfoundry.sh/getting-started/installation). If you don't already have it installed, make sure you restart your shell.

``` shell
foundryup
```

Next, build the smart contracts.

```
yarn build
```

Afterwards, enter the bindings directory:

```
cd bindings
```

And run the following commands to generate the types and bindings:

```
yarn bindings
yarn tsc
```

With the bindings generated, you may publish to npm using the following command:

```
npm publish
```

You must have the relevant access permissions to publish this crate.
You can check these by seeing whether `tap-contracts-bindings` is listed as `read-write` under

``` shell
npm access list packages
```
