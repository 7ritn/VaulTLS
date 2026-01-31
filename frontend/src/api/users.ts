import ApiClient from './ApiClient';
import type {CreateUserRequest, User} from "@/types/User.ts";
export const fetchUsers = async (): Promise<User[]> => {
    return await ApiClient.get<User[]>('/users');
};

export const createUser = async (createUserReq: CreateUserRequest): Promise<number> => {
    const user = await ApiClient.post<User>('/users', createUserReq);
    return user.id;
};

export const deleteUser = async (id: number): Promise<void> => {
    await ApiClient.delete<void>(`/users/${id}`);
    await fetchUsers();
};

export const updateUser = async (user: User): Promise<void> => {
    return await ApiClient.put<void>(`/users/${user.id}`, user);
};
