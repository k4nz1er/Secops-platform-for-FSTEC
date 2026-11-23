const keycloak = {
  authenticated: true,
  token: "",
  tokenParsed: {
    preferred_username: "admin",
    realm_access: { roles: ["admin", "specialist"] },
  },
  init: (_options?: unknown) => Promise.resolve(true),
  updateToken: (_minValidity?: number) => Promise.resolve(false),
  login: (_options?: unknown) => Promise.resolve(),
  logout: (_options?: unknown) => Promise.resolve(),
};

export default keycloak;
