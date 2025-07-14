import type {SetupReq, IsSetupResponse, ChangePasswordReq} from "@/types/Login.ts";
import ApiClient from "@/api/ApiClient.ts";
import type {User} from "@/types/User.ts";

export const is_setup = async (): Promise<IsSetupResponse> => {
    return await ApiClient.get<IsSetupResponse>('/server/setup');
};


export const setup = async (setupReq: SetupReq): Promise<void> => {
    return await ApiClient.post<void>('/server/setup', setupReq);
};

export const login = async (loginReq: { email: string | undefined, password: string | undefined }): Promise<void> => {
    return await ApiClient.post<void>('/auth/login', loginReq);
};

export const change_password = async (changePasswordReq: ChangePasswordReq): Promise<void> => {
    return await ApiClient.post<void>('/auth/change_password', changePasswordReq);
};

export const logout = async (): Promise<void> => {
    return await ApiClient.post<void>('/auth/logout');
};

export const current_user = async (): Promise<User> => {
    return await ApiClient.get<User>('/auth/me');
}