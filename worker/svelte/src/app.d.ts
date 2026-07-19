declare global {
  namespace App {
    interface Platform {
      env: {
        VAULT_DB: D1Database;
        AUTHN_URL: string;
        ASSETS: Fetcher;
      };
    }
  }
}

export {};
