import { shouldSupportInterfaces } from "@ensdomains/hardhat-chai-matchers-viem/behaviour";
import hre from "hardhat";
import { describe, it } from "vitest";

import {
  COIN_TYPE_DEFAULT,
  COIN_TYPE_ETH,
  type KnownProfile,
  bundleCalls,
  makeResolutions,
} from "../../utils/resolutions.js";
import { shouldSupportFeatures } from "../../utils/supportsFeatures.js";
import { dnsEncodeName } from "../../utils/utils.js";
import { deployV1Fixture } from "../fixtures/deployV1Fixture.js";
import { deployV2Fixture } from "../fixtures/deployV2Fixture.js";
import {
  getAddress,
  getContract,
  parseEventLogs,
  zeroAddress,
  type Address,
} from "viem";
import { waitForSuccessfulTransactionReceipt } from "../../utils/waitForSuccessfulTransactionReceipt.js";
import { expectVar } from "../../utils/expectVar.ts";

const network = await hre.network.connect();

const KP: KnownProfile = {
  name: "test.eth",
  addresses: [
    {
      coinType: COIN_TYPE_ETH,
      value: "0x8000000000000000000000000000000000000001",
    },
    {
      coinType: COIN_TYPE_DEFAULT,
      value: "0x8000000000000000000000000000000000000002",
    },
    { coinType: 0n, value: "0x1234" },
  ],
  texts: [{ key: "url", value: "https://ens.domains" }],
  contenthash: { value: "0x123456" },
};

async function fixture() {
  const mainnetV1 = await deployV1Fixture(network, true);
  const mainnetV2 = await deployV2Fixture(network, true);
  const aliasResolver = await network.viem.deployContract("AliasResolver", [
    mainnetV2.rootRegistry.address,
    mainnetV2.batchGatewayProvider.address,
  ]);
  const ssResolver = await network.viem.deployContract(
    "DummyShapeshiftResolver",
  );
  return { mainnetV1, mainnetV2, aliasResolver, ssResolver, createAlias };
  async function createAlias({
    name = undefined,
    resolver = zeroAddress,
  }: {
    name?: string;
    resolver?: Address;
  }) {
    const hash = await aliasResolver.write.createAlias([
      resolver,
      name === undefined ? "0x" : dnsEncodeName(name),
    ]);
    const receipt = await waitForSuccessfulTransactionReceipt(
      mainnetV2.walletClient,
      { hash },
    );
    const [log] = parseEventLogs({
      abi: aliasResolver.abi,
      eventName: "AliasCreated",
      logs: receipt.logs,
    });
    return getContract({
      abi: aliasResolver.abi,
      address: log.args.clone,
      client: mainnetV2.walletClient,
    });
  }
}

describe("AliasResolver", () => {
  shouldSupportInterfaces({
    contract: () =>
      network.networkHelpers.loadFixture(fixture).then((F) => F.aliasResolver),
    interfaces: [
      "IERC165",
      "IERC7996",
      "IExtendedResolver",
      "ICompositeResolver",
    ],
  });

  shouldSupportFeatures({
    contract: () =>
      network.networkHelpers.loadFixture(fixture).then((F) => F.aliasResolver),
    features: {
      RESOLVER: ["RESOLVE_MULTICALL"],
    },
  });

  describe("getAlias()", () => {
    it("no resolver", async () => {
      const F = await network.networkHelpers.loadFixture(fixture);
      const aliasResolver = await F.createAlias({
        name: KP.name,
      });
      const [resolver, name] = await aliasResolver.read.getAlias();
      expectVar({ resolver }).toStrictEqual(zeroAddress);
      expectVar({ name }).toStrictEqual(dnsEncodeName(KP.name));
    });

    it("no name", async () => {
      const F = await network.networkHelpers.loadFixture(fixture);
      const aliasResolver = await F.createAlias({
        resolver: F.ssResolver.address,
      });
      const [resolver, name] = await aliasResolver.read.getAlias();
      expectVar({ resolver }).toStrictEqual(getAddress(F.ssResolver.address));
      expectVar({ name }).toStrictEqual("0x");
    });

    it("both", async () => {
      const F = await network.networkHelpers.loadFixture(fixture);
      const aliasResolver = await F.createAlias({
        name: KP.name,
        resolver: F.ssResolver.address,
      });
      const [resolver, name] = await aliasResolver.read.getAlias();
      expectVar({ resolver }).toStrictEqual(getAddress(F.ssResolver.address));
      expectVar({ name }).toStrictEqual(dnsEncodeName(KP.name));
    });
  });

  // TODO: more cases
  it("alias", async () => {
    const F = await network.networkHelpers.loadFixture(fixture);
    const { dedicatedResolver } = await F.mainnetV2.setupName(KP);
    await dedicatedResolver.write.multicall([
      [bundleCalls(makeResolutions(KP)).writeDedicated],
    ]);
    const aliasResolver = await F.createAlias(KP);
    const kp: KnownProfile = { ...KP, name: "alias.eth" };
    await F.mainnetV2.setupName({
      name: kp.name,
      resolverAddress: aliasResolver.address,
    });
    const res = bundleCalls(makeResolutions(kp));
    res.expect(
      await aliasResolver.read.resolve([dnsEncodeName(kp.name), res.call]),
    );
  });
});
