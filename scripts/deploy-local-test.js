// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// You can also run a script with `npx hardhat run <script>`. If you do that, Hardhat
// will compile your contracts, add the Hardhat Runtime Environment's members to the
// global scope, and execute the script.
const hre = require("hardhat");
const chalk = require('chalk')

async function main() {
    // Get signers
    [owner] = await ethers.getSigners();

    // Library deployment
    const libg1 = await ethers.getContractFactory("BN256G1", { signer: owner });
    const libg1Instance = await libg1.deploy();
    const libg2 = await ethers.getContractFactory("BN256G2", { signer: owner });
    const libg2Instance = await libg2.deploy();
    const libpairing = await ethers.getContractFactory("Pairing", { signer: owner,
        //libraries: {
            //BN256G1: libg1Instance,
            //BN256G2: libg2Instance
        //},
    });
    const libpairingInstance = await libpairing.deploy();

    // Deploy the ServiceNodeRewards contract
    BLSSafe = await ethers.getContractFactory("BLSSafe", {
        libraries: {
            BN256G1: libg1Instance,
            BN256G2: libg2Instance,
            //Pairing: libpairingInstance
        }
    });
    blsSafe = await BLSSafe.deploy();

    await blsSafe.waitForDeployment();

    console.log(
        '  ',
        chalk.cyan(`BLS Safe Contract`),
        'deployed to:',
        chalk.greenBright(await blsSafe.getAddress()),
    )
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
