// A detector fixture that always throws. Used to prove the pipeline isolates a
// misbehaving plugin: it must never crash the wire or stop other detectors.
export default {
  name: "throwing-detector",
  inspect() {
    throw new Error("detector plugin boom");
  },
};
