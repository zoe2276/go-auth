export interface ApiParameters {
    headers?: Headers
    body?: string
}

async function callApi<T>(endpoint: string, params: ApiParameters): Promise<T> {
    const res = await fetch(`${import.meta.env.VITE_BASE_URL}${endpoint}`, params)

    if (!res.ok) throw new Error(res.statusText)
    return await res.json() as T
}

export const register = async (username: string, password: string, email: string, role: string = "user") => {
    const registrationObj = {
        username: username,
        password: password,
        email: email,
        role: role
    }

    return await callApi<{ message: string }>("/api/register", {
        body: JSON.stringify(registrationObj)
    })
}

export const login = async (username: string, password: string) => {
    const credsObj = {
        username: username,
        password: password
    }

    return await callApi<{ token: string, expiration: string}>("/api/token", {
        body: JSON.stringify(credsObj)
    })
}