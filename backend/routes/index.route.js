const LogRoutes = require("./log.route");
const UserRoutes = require("./user.route");
const RfidRoutes = require("./rfid.route");
const FingerprintRoutes = require("./fingerprint.route");
const DeviceRoutes = require("./device.route");
const OrganizationRoutes = require("./organization.route");
const notificationRoute = require("./notification.route");
const faceRoute = require("./face.route");
const statsRoute = require("./stats.route");

module.exports = (app) => {
  app.use("/log", LogRoutes);

  app.use("/user", UserRoutes);

  app.use("/rfid", RfidRoutes);

  app.use("/fingerprint", FingerprintRoutes);

  app.use("/device", DeviceRoutes);

  app.use("/organization", OrganizationRoutes);

  app.use("/notification", notificationRoute);

  app.use("/face", faceRoute);

  app.use("/stats", statsRoute);
};
