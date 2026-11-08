const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-toolbox/network-helpers");

const H1 = ethers.id("report-1"); // keccak of a string: any 32-byte value works as a test hash
const H2 = ethers.id("report-2");
const H3 = ethers.id("report-1-corrected");

describe("ThreatRegistry", function () {
  async function deploy() {
    const [owner, other] = await ethers.getSigners();
    const registry = await ethers.deployContract("ThreatRegistry");
    return { registry, owner, other };
  }

  it("registers a report hash and returns it with metadata", async function () {
    const { registry, owner } = await loadFixture(deploy);
    await expect(registry.submitReport(H1, "high_risk"))
      .to.emit(registry, "ReportSubmitted")
      .withArgs(1, H1, owner.address, (t) => t > 0n);
    const [hash, submitter, timestamp, risk, status, revisions] = await registry.getReport(1);
    expect(hash).to.equal(H1);
    expect(submitter).to.equal(owner.address);
    expect(timestamp).to.be.greaterThan(0n);
    expect(risk).to.equal("high_risk");
    expect(status).to.equal(0); // Active
    expect(revisions).to.equal(0);
    expect(await registry.reportCount()).to.equal(1);
    expect(await registry.idOfHash(H1)).to.equal(1);
    expect(await registry.verify(1, H1)).to.equal(true);
    expect(await registry.verify(1, H2)).to.equal(false);
  });

  it("assigns sequential ids starting at 1", async function () {
    const { registry } = await loadFixture(deploy);
    await registry.submitReport(H1, "suspicious");
    await registry.submitReport(H2, "low_risk");
    expect(await registry.reportCount()).to.equal(2);
    expect((await registry.getReport(2))[0]).to.equal(H2);
  });

  it("rejects empty hashes, duplicate hashes and bad risk labels", async function () {
    const { registry } = await loadFixture(deploy);
    await expect(registry.submitReport(ethers.ZeroHash, "high_risk")).to.be.revertedWithCustomError(registry, "EmptyHash");
    await registry.submitReport(H1, "high_risk");
    await expect(registry.submitReport(H1, "high_risk"))
      .to.be.revertedWithCustomError(registry, "HashAlreadyRegistered")
      .withArgs(H1, 1);
    await expect(registry.submitReport(H2, "")).to.be.revertedWithCustomError(registry, "InvalidText");
    await expect(registry.submitReport(H2, "x".repeat(33))).to.be.revertedWithCustomError(registry, "InvalidText");
  });

  it("rejects unknown report ids", async function () {
    const { registry } = await loadFixture(deploy);
    await expect(registry.getReport(0)).to.be.revertedWithCustomError(registry, "UnknownReport").withArgs(0);
    await expect(registry.getReport(99)).to.be.revertedWithCustomError(registry, "UnknownReport").withArgs(99);
    await expect(registry.disputeReport(5, "FALSE_POSITIVE")).to.be.revertedWithCustomError(registry, "UnknownReport");
  });

  it("lets only the submitter revise, and keeps the full history", async function () {
    const { registry, other } = await loadFixture(deploy);
    await registry.submitReport(H1, "high_risk");
    await expect(registry.connect(other).reviseReport(1, H3)).to.be.revertedWithCustomError(registry, "NotSubmitter");
    await expect(registry.reviseReport(1, H3)).to.emit(registry, "ReportRevised").withArgs(1, H3, 1);
    const [hash, , , , status, revisions] = await registry.getReport(1);
    expect(hash).to.equal(H3);
    expect(status).to.equal(2); // Revised
    expect(revisions).to.equal(1);
    expect(await registry.getHistory(1)).to.deep.equal([H1, H3]);
    expect(await registry.verify(1, H1)).to.equal(false); // old version is no longer current
  });

  it("lets anyone dispute with a short reason code", async function () {
    const { registry, other } = await loadFixture(deploy);
    await registry.submitReport(H1, "high_risk");
    await expect(registry.connect(other).disputeReport(1, "FALSE_POSITIVE"))
      .to.emit(registry, "ReportDisputed")
      .withArgs(1, other.address, "FALSE_POSITIVE");
    expect((await registry.getReport(1))[4]).to.equal(1); // Disputed
    expect(await registry.disputeCount(1)).to.equal(1);
    await expect(registry.disputeReport(1, "")).to.be.revertedWithCustomError(registry, "InvalidText");
  });
});
