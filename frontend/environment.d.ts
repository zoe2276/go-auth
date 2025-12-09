declare global {
    namespace NodeJS {
        interface ProcessEnv {
            VITE_BASE_URL: "127.0.0.1:8099" | "https://auth.zoe.rip"
        }
    }
}

export {}