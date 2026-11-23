import axios, { AxiosError, InternalAxiosRequestConfig } from "axios";
import keycloak from "../services/keycloak";

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "/api/v1",
  timeout: 30000,
});

apiClient.interceptors.request.use(
  async (config: InternalAxiosRequestConfig) => {
    if (keycloak.authenticated) {
      try {
        await keycloak.updateToken(30);
      } catch {
        keycloak.login();
        return Promise.reject(new Error("Сессия истекла, требуется повторный вход"));
      }

      if (keycloak.token) {
        config.headers.Authorization = `Bearer ${keycloak.token}`;
      }
    }
    return config;
  },
  (error: AxiosError) => Promise.reject(error)
);

apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      keycloak.login();
    }
    return Promise.reject(error);
  }
);

export default apiClient;
