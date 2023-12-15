# Timeline Aggregation Protocol (TAP) Contract(s)

## Create types and bindings

First, use forge to build the smart contracts:

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
