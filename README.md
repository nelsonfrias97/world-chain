# World Chain Builder

The World Chain Builder is a custom block builder for the OP Stack that provides Priority Blockspace for Humans (PBH). PBH enables verified World ID users to execute transactions with top of block priority, enabling a more frictionless user experience. This mechanism is designed to ensure that ordinary users aren’t unfairly disadvantaged by automated systems and greatly mitigates the impact of negative impacts of MEV. PBH also enables future flexibility, allowing for a separate EIP-1559-style fee market mechanism for verified transactions.


<div align="center">
  <img src="assets/pbh-op-stack.png" alt="World Chain Builder Architecture" width="70%">
</div>

To learn more about how PBH works, check out the docs detailing [the PBH Transaction Lifecycle](world-chain-builder/docs/pbh_tx_lifecycle.md), [World's blog post covering World Chain's builder architecture](https://world.org/blog/engineering/introducing-pbh-priority-blockspace-for-humans), and [the PBH architecture](world-chain-builder/docs/pbh_architecture.md).


<!-- ## Installing -->

## Running the Devnet
To spin up a OP Stack devnet with `rollup-boost` and the `world-chain-builder` deployed, make sure that you have [just](https://github.com/casey/just?tab=readme-ov-file) installed, and docker daemon running. Then simply run the following command.

```
just devnet-up
```

To stop the devnet and clean up all resources, run the command below.

```
just devnet-down
```
