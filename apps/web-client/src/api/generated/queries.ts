/**
 * Generated by orval v7.4.1 🍺
 * Do not edit manually.
 * Test API
 * Test Application Rest Api
 * OpenAPI spec version: 0.0.1
 */
import { useMutation, useQuery } from "@tanstack/react-query";
import type {
  DataTag,
  DefinedInitialDataOptions,
  DefinedUseQueryResult,
  MutationFunction,
  QueryFunction,
  QueryKey,
  UndefinedInitialDataOptions,
  UseMutationOptions,
  UseMutationResult,
  UseQueryOptions,
  UseQueryResult,
} from "@tanstack/react-query";

import { axiosInstance } from "../../config/axios.config";
import type {
  CreateUserDto,
  SigninDto,
  SignupDto,
  TokenDto,
  UpdateUserDto,
  UserResponseDto,
} from "./";

export const appControllerGetHello = (signal?: AbortSignal) => {
  return axiosInstance<void>({ url: `/api`, method: "GET", signal });
};

export const getAppControllerGetHelloQueryKey = () => {
  return [`/api`] as const;
};

export const getAppControllerGetHelloQueryOptions = <
  TData = Awaited<ReturnType<typeof appControllerGetHello>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof appControllerGetHello>>,
      TError,
      TData
    >
  >;
}) => {
  const { query: queryOptions } = options ?? {};

  const queryKey = queryOptions?.queryKey ?? getAppControllerGetHelloQueryKey();

  const queryFn: QueryFunction<
    Awaited<ReturnType<typeof appControllerGetHello>>
  > = ({ signal }) => appControllerGetHello(signal);

  return { queryKey, queryFn, ...queryOptions } as UseQueryOptions<
    Awaited<ReturnType<typeof appControllerGetHello>>,
    TError,
    TData
  > & { queryKey: DataTag<QueryKey, TData, TError> };
};

export type AppControllerGetHelloQueryResult = NonNullable<
  Awaited<ReturnType<typeof appControllerGetHello>>
>;
export type AppControllerGetHelloQueryError = unknown;

export function useAppControllerGetHello<
  TData = Awaited<ReturnType<typeof appControllerGetHello>>,
  TError = unknown,
>(options: {
  query: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof appControllerGetHello>>,
      TError,
      TData
    >
  > &
    Pick<
      DefinedInitialDataOptions<
        Awaited<ReturnType<typeof appControllerGetHello>>,
        TError,
        TData
      >,
      "initialData"
    >;
}): DefinedUseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};
export function useAppControllerGetHello<
  TData = Awaited<ReturnType<typeof appControllerGetHello>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof appControllerGetHello>>,
      TError,
      TData
    >
  > &
    Pick<
      UndefinedInitialDataOptions<
        Awaited<ReturnType<typeof appControllerGetHello>>,
        TError,
        TData
      >,
      "initialData"
    >;
}): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};
export function useAppControllerGetHello<
  TData = Awaited<ReturnType<typeof appControllerGetHello>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof appControllerGetHello>>,
      TError,
      TData
    >
  >;
}): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};

export function useAppControllerGetHello<
  TData = Awaited<ReturnType<typeof appControllerGetHello>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof appControllerGetHello>>,
      TError,
      TData
    >
  >;
}): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
} {
  const queryOptions = getAppControllerGetHelloQueryOptions(options);

  const query = useQuery(queryOptions) as UseQueryResult<TData, TError> & {
    queryKey: DataTag<QueryKey, TData, TError>;
  };

  query.queryKey = queryOptions.queryKey;

  return query;
}

export const authControllerSignin = (
  signinDto: SigninDto,
  signal?: AbortSignal
) => {
  return axiosInstance<TokenDto>({
    url: `/api/auth/signin`,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    data: signinDto,
    signal,
  });
};

export const getAuthControllerSigninMutationOptions = <
  TData = Awaited<ReturnType<typeof authControllerSignin>>,
  TError = unknown,
  TContext = unknown,
>(options?: {
  mutation?: UseMutationOptions<TData, TError, { data: SigninDto }, TContext>;
}) => {
  const mutationKey = ["authControllerSignin"];
  const { mutation: mutationOptions } = options
    ? options.mutation &&
      "mutationKey" in options.mutation &&
      options.mutation.mutationKey
      ? options
      : { ...options, mutation: { ...options.mutation, mutationKey } }
    : { mutation: { mutationKey } };

  const mutationFn: MutationFunction<
    Awaited<ReturnType<typeof authControllerSignin>>,
    { data: SigninDto }
  > = (props) => {
    const { data } = props ?? {};

    return authControllerSignin(data);
  };

  return { mutationFn, ...mutationOptions } as UseMutationOptions<
    TData,
    TError,
    { data: SigninDto },
    TContext
  >;
};

export type AuthControllerSigninMutationResult = NonNullable<
  Awaited<ReturnType<typeof authControllerSignin>>
>;
export type AuthControllerSigninMutationBody = SigninDto;
export type AuthControllerSigninMutationError = unknown;

export const useAuthControllerSignin = <
  TData = Awaited<ReturnType<typeof authControllerSignin>>,
  TError = unknown,
  TContext = unknown,
>(options?: {
  mutation?: UseMutationOptions<TData, TError, { data: SigninDto }, TContext>;
}): UseMutationResult<TData, TError, { data: SigninDto }, TContext> => {
  const mutationOptions = getAuthControllerSigninMutationOptions(options);

  return useMutation(mutationOptions);
};

export const authControllerSignup = (
  signupDto: SignupDto,
  signal?: AbortSignal
) => {
  return axiosInstance<TokenDto>({
    url: `/api/auth/signup`,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    data: signupDto,
    signal,
  });
};

export const getAuthControllerSignupMutationOptions = <
  TData = Awaited<ReturnType<typeof authControllerSignup>>,
  TError = unknown,
  TContext = unknown,
>(options?: {
  mutation?: UseMutationOptions<TData, TError, { data: SignupDto }, TContext>;
}) => {
  const mutationKey = ["authControllerSignup"];
  const { mutation: mutationOptions } = options
    ? options.mutation &&
      "mutationKey" in options.mutation &&
      options.mutation.mutationKey
      ? options
      : { ...options, mutation: { ...options.mutation, mutationKey } }
    : { mutation: { mutationKey } };

  const mutationFn: MutationFunction<
    Awaited<ReturnType<typeof authControllerSignup>>,
    { data: SignupDto }
  > = (props) => {
    const { data } = props ?? {};

    return authControllerSignup(data);
  };

  return { mutationFn, ...mutationOptions } as UseMutationOptions<
    TData,
    TError,
    { data: SignupDto },
    TContext
  >;
};

export type AuthControllerSignupMutationResult = NonNullable<
  Awaited<ReturnType<typeof authControllerSignup>>
>;
export type AuthControllerSignupMutationBody = SignupDto;
export type AuthControllerSignupMutationError = unknown;

export const useAuthControllerSignup = <
  TData = Awaited<ReturnType<typeof authControllerSignup>>,
  TError = unknown,
  TContext = unknown,
>(options?: {
  mutation?: UseMutationOptions<TData, TError, { data: SignupDto }, TContext>;
}): UseMutationResult<TData, TError, { data: SignupDto }, TContext> => {
  const mutationOptions = getAuthControllerSignupMutationOptions(options);

  return useMutation(mutationOptions);
};

export const authControllerGoogleLogin = (signal?: AbortSignal) => {
  return axiosInstance<void>({
    url: `/api/auth/google/login`,
    method: "GET",
    signal,
  });
};

export const getAuthControllerGoogleLoginQueryKey = () => {
  return [`/api/auth/google/login`] as const;
};

export const getAuthControllerGoogleLoginQueryOptions = <
  TData = Awaited<ReturnType<typeof authControllerGoogleLogin>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof authControllerGoogleLogin>>,
      TError,
      TData
    >
  >;
}) => {
  const { query: queryOptions } = options ?? {};

  const queryKey =
    queryOptions?.queryKey ?? getAuthControllerGoogleLoginQueryKey();

  const queryFn: QueryFunction<
    Awaited<ReturnType<typeof authControllerGoogleLogin>>
  > = ({ signal }) => authControllerGoogleLogin(signal);

  return { queryKey, queryFn, ...queryOptions } as UseQueryOptions<
    Awaited<ReturnType<typeof authControllerGoogleLogin>>,
    TError,
    TData
  > & { queryKey: DataTag<QueryKey, TData, TError> };
};

export type AuthControllerGoogleLoginQueryResult = NonNullable<
  Awaited<ReturnType<typeof authControllerGoogleLogin>>
>;
export type AuthControllerGoogleLoginQueryError = unknown;

export function useAuthControllerGoogleLogin<
  TData = Awaited<ReturnType<typeof authControllerGoogleLogin>>,
  TError = unknown,
>(options: {
  query: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof authControllerGoogleLogin>>,
      TError,
      TData
    >
  > &
    Pick<
      DefinedInitialDataOptions<
        Awaited<ReturnType<typeof authControllerGoogleLogin>>,
        TError,
        TData
      >,
      "initialData"
    >;
}): DefinedUseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};
export function useAuthControllerGoogleLogin<
  TData = Awaited<ReturnType<typeof authControllerGoogleLogin>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof authControllerGoogleLogin>>,
      TError,
      TData
    >
  > &
    Pick<
      UndefinedInitialDataOptions<
        Awaited<ReturnType<typeof authControllerGoogleLogin>>,
        TError,
        TData
      >,
      "initialData"
    >;
}): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};
export function useAuthControllerGoogleLogin<
  TData = Awaited<ReturnType<typeof authControllerGoogleLogin>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof authControllerGoogleLogin>>,
      TError,
      TData
    >
  >;
}): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};

export function useAuthControllerGoogleLogin<
  TData = Awaited<ReturnType<typeof authControllerGoogleLogin>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof authControllerGoogleLogin>>,
      TError,
      TData
    >
  >;
}): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
} {
  const queryOptions = getAuthControllerGoogleLoginQueryOptions(options);

  const query = useQuery(queryOptions) as UseQueryResult<TData, TError> & {
    queryKey: DataTag<QueryKey, TData, TError>;
  };

  query.queryKey = queryOptions.queryKey;

  return query;
}

export const authControllerGoogleCallback = (signal?: AbortSignal) => {
  return axiosInstance<void>({
    url: `/api/auth/google/callback`,
    method: "GET",
    signal,
  });
};

export const getAuthControllerGoogleCallbackQueryKey = () => {
  return [`/api/auth/google/callback`] as const;
};

export const getAuthControllerGoogleCallbackQueryOptions = <
  TData = Awaited<ReturnType<typeof authControllerGoogleCallback>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof authControllerGoogleCallback>>,
      TError,
      TData
    >
  >;
}) => {
  const { query: queryOptions } = options ?? {};

  const queryKey =
    queryOptions?.queryKey ?? getAuthControllerGoogleCallbackQueryKey();

  const queryFn: QueryFunction<
    Awaited<ReturnType<typeof authControllerGoogleCallback>>
  > = ({ signal }) => authControllerGoogleCallback(signal);

  return { queryKey, queryFn, ...queryOptions } as UseQueryOptions<
    Awaited<ReturnType<typeof authControllerGoogleCallback>>,
    TError,
    TData
  > & { queryKey: DataTag<QueryKey, TData, TError> };
};

export type AuthControllerGoogleCallbackQueryResult = NonNullable<
  Awaited<ReturnType<typeof authControllerGoogleCallback>>
>;
export type AuthControllerGoogleCallbackQueryError = unknown;

export function useAuthControllerGoogleCallback<
  TData = Awaited<ReturnType<typeof authControllerGoogleCallback>>,
  TError = unknown,
>(options: {
  query: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof authControllerGoogleCallback>>,
      TError,
      TData
    >
  > &
    Pick<
      DefinedInitialDataOptions<
        Awaited<ReturnType<typeof authControllerGoogleCallback>>,
        TError,
        TData
      >,
      "initialData"
    >;
}): DefinedUseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};
export function useAuthControllerGoogleCallback<
  TData = Awaited<ReturnType<typeof authControllerGoogleCallback>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof authControllerGoogleCallback>>,
      TError,
      TData
    >
  > &
    Pick<
      UndefinedInitialDataOptions<
        Awaited<ReturnType<typeof authControllerGoogleCallback>>,
        TError,
        TData
      >,
      "initialData"
    >;
}): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};
export function useAuthControllerGoogleCallback<
  TData = Awaited<ReturnType<typeof authControllerGoogleCallback>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof authControllerGoogleCallback>>,
      TError,
      TData
    >
  >;
}): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};

export function useAuthControllerGoogleCallback<
  TData = Awaited<ReturnType<typeof authControllerGoogleCallback>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof authControllerGoogleCallback>>,
      TError,
      TData
    >
  >;
}): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
} {
  const queryOptions = getAuthControllerGoogleCallbackQueryOptions(options);

  const query = useQuery(queryOptions) as UseQueryResult<TData, TError> & {
    queryKey: DataTag<QueryKey, TData, TError>;
  };

  query.queryKey = queryOptions.queryKey;

  return query;
}

export const authControllerRefreshToken = (signal?: AbortSignal) => {
  return axiosInstance<TokenDto>({
    url: `/api/auth/refresh`,
    method: "POST",
    signal,
  });
};

export const getAuthControllerRefreshTokenMutationOptions = <
  TData = Awaited<ReturnType<typeof authControllerRefreshToken>>,
  TError = unknown,
  TContext = unknown,
>(options?: {
  mutation?: UseMutationOptions<TData, TError, void, TContext>;
}) => {
  const mutationKey = ["authControllerRefreshToken"];
  const { mutation: mutationOptions } = options
    ? options.mutation &&
      "mutationKey" in options.mutation &&
      options.mutation.mutationKey
      ? options
      : { ...options, mutation: { ...options.mutation, mutationKey } }
    : { mutation: { mutationKey } };

  const mutationFn: MutationFunction<
    Awaited<ReturnType<typeof authControllerRefreshToken>>,
    void
  > = () => {
    return authControllerRefreshToken();
  };

  return { mutationFn, ...mutationOptions } as UseMutationOptions<
    TData,
    TError,
    void,
    TContext
  >;
};

export type AuthControllerRefreshTokenMutationResult = NonNullable<
  Awaited<ReturnType<typeof authControllerRefreshToken>>
>;

export type AuthControllerRefreshTokenMutationError = unknown;

export const useAuthControllerRefreshToken = <
  TData = Awaited<ReturnType<typeof authControllerRefreshToken>>,
  TError = unknown,
  TContext = unknown,
>(options?: {
  mutation?: UseMutationOptions<TData, TError, void, TContext>;
}): UseMutationResult<TData, TError, void, TContext> => {
  const mutationOptions = getAuthControllerRefreshTokenMutationOptions(options);

  return useMutation(mutationOptions);
};

export const authControllerLogout = (signal?: AbortSignal) => {
  return axiosInstance<void>({
    url: `/api/auth/logout`,
    method: "POST",
    signal,
  });
};

export const getAuthControllerLogoutMutationOptions = <
  TData = Awaited<ReturnType<typeof authControllerLogout>>,
  TError = unknown,
  TContext = unknown,
>(options?: {
  mutation?: UseMutationOptions<TData, TError, void, TContext>;
}) => {
  const mutationKey = ["authControllerLogout"];
  const { mutation: mutationOptions } = options
    ? options.mutation &&
      "mutationKey" in options.mutation &&
      options.mutation.mutationKey
      ? options
      : { ...options, mutation: { ...options.mutation, mutationKey } }
    : { mutation: { mutationKey } };

  const mutationFn: MutationFunction<
    Awaited<ReturnType<typeof authControllerLogout>>,
    void
  > = () => {
    return authControllerLogout();
  };

  return { mutationFn, ...mutationOptions } as UseMutationOptions<
    TData,
    TError,
    void,
    TContext
  >;
};

export type AuthControllerLogoutMutationResult = NonNullable<
  Awaited<ReturnType<typeof authControllerLogout>>
>;

export type AuthControllerLogoutMutationError = unknown;

export const useAuthControllerLogout = <
  TData = Awaited<ReturnType<typeof authControllerLogout>>,
  TError = unknown,
  TContext = unknown,
>(options?: {
  mutation?: UseMutationOptions<TData, TError, void, TContext>;
}): UseMutationResult<TData, TError, void, TContext> => {
  const mutationOptions = getAuthControllerLogoutMutationOptions(options);

  return useMutation(mutationOptions);
};

export const usersControllerMe = (signal?: AbortSignal) => {
  return axiosInstance<UserResponseDto>({
    url: `/api/users/me`,
    method: "GET",
    signal,
  });
};

export const getUsersControllerMeQueryKey = () => {
  return [`/api/users/me`] as const;
};

export const getUsersControllerMeQueryOptions = <
  TData = Awaited<ReturnType<typeof usersControllerMe>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof usersControllerMe>>,
      TError,
      TData
    >
  >;
}) => {
  const { query: queryOptions } = options ?? {};

  const queryKey = queryOptions?.queryKey ?? getUsersControllerMeQueryKey();

  const queryFn: QueryFunction<
    Awaited<ReturnType<typeof usersControllerMe>>
  > = ({ signal }) => usersControllerMe(signal);

  return { queryKey, queryFn, ...queryOptions } as UseQueryOptions<
    Awaited<ReturnType<typeof usersControllerMe>>,
    TError,
    TData
  > & { queryKey: DataTag<QueryKey, TData, TError> };
};

export type UsersControllerMeQueryResult = NonNullable<
  Awaited<ReturnType<typeof usersControllerMe>>
>;
export type UsersControllerMeQueryError = unknown;

export function useUsersControllerMe<
  TData = Awaited<ReturnType<typeof usersControllerMe>>,
  TError = unknown,
>(options: {
  query: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof usersControllerMe>>,
      TError,
      TData
    >
  > &
    Pick<
      DefinedInitialDataOptions<
        Awaited<ReturnType<typeof usersControllerMe>>,
        TError,
        TData
      >,
      "initialData"
    >;
}): DefinedUseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};
export function useUsersControllerMe<
  TData = Awaited<ReturnType<typeof usersControllerMe>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof usersControllerMe>>,
      TError,
      TData
    >
  > &
    Pick<
      UndefinedInitialDataOptions<
        Awaited<ReturnType<typeof usersControllerMe>>,
        TError,
        TData
      >,
      "initialData"
    >;
}): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};
export function useUsersControllerMe<
  TData = Awaited<ReturnType<typeof usersControllerMe>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof usersControllerMe>>,
      TError,
      TData
    >
  >;
}): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};

export function useUsersControllerMe<
  TData = Awaited<ReturnType<typeof usersControllerMe>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof usersControllerMe>>,
      TError,
      TData
    >
  >;
}): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
} {
  const queryOptions = getUsersControllerMeQueryOptions(options);

  const query = useQuery(queryOptions) as UseQueryResult<TData, TError> & {
    queryKey: DataTag<QueryKey, TData, TError>;
  };

  query.queryKey = queryOptions.queryKey;

  return query;
}

export const usersControllerCreateUser = (
  createUserDto: CreateUserDto,
  signal?: AbortSignal
) => {
  return axiosInstance<UserResponseDto>({
    url: `/api/users`,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    data: createUserDto,
    signal,
  });
};

export const getUsersControllerCreateUserMutationOptions = <
  TData = Awaited<ReturnType<typeof usersControllerCreateUser>>,
  TError = unknown,
  TContext = unknown,
>(options?: {
  mutation?: UseMutationOptions<
    TData,
    TError,
    { data: CreateUserDto },
    TContext
  >;
}) => {
  const mutationKey = ["usersControllerCreateUser"];
  const { mutation: mutationOptions } = options
    ? options.mutation &&
      "mutationKey" in options.mutation &&
      options.mutation.mutationKey
      ? options
      : { ...options, mutation: { ...options.mutation, mutationKey } }
    : { mutation: { mutationKey } };

  const mutationFn: MutationFunction<
    Awaited<ReturnType<typeof usersControllerCreateUser>>,
    { data: CreateUserDto }
  > = (props) => {
    const { data } = props ?? {};

    return usersControllerCreateUser(data);
  };

  return { mutationFn, ...mutationOptions } as UseMutationOptions<
    TData,
    TError,
    { data: CreateUserDto },
    TContext
  >;
};

export type UsersControllerCreateUserMutationResult = NonNullable<
  Awaited<ReturnType<typeof usersControllerCreateUser>>
>;
export type UsersControllerCreateUserMutationBody = CreateUserDto;
export type UsersControllerCreateUserMutationError = unknown;

export const useUsersControllerCreateUser = <
  TData = Awaited<ReturnType<typeof usersControllerCreateUser>>,
  TError = unknown,
  TContext = unknown,
>(options?: {
  mutation?: UseMutationOptions<
    TData,
    TError,
    { data: CreateUserDto },
    TContext
  >;
}): UseMutationResult<TData, TError, { data: CreateUserDto }, TContext> => {
  const mutationOptions = getUsersControllerCreateUserMutationOptions(options);

  return useMutation(mutationOptions);
};

export const usersControllerFindAll = (signal?: AbortSignal) => {
  return axiosInstance<UserResponseDto[]>({
    url: `/api/users`,
    method: "GET",
    signal,
  });
};

export const getUsersControllerFindAllQueryKey = () => {
  return [`/api/users`] as const;
};

export const getUsersControllerFindAllQueryOptions = <
  TData = Awaited<ReturnType<typeof usersControllerFindAll>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof usersControllerFindAll>>,
      TError,
      TData
    >
  >;
}) => {
  const { query: queryOptions } = options ?? {};

  const queryKey =
    queryOptions?.queryKey ?? getUsersControllerFindAllQueryKey();

  const queryFn: QueryFunction<
    Awaited<ReturnType<typeof usersControllerFindAll>>
  > = ({ signal }) => usersControllerFindAll(signal);

  return { queryKey, queryFn, ...queryOptions } as UseQueryOptions<
    Awaited<ReturnType<typeof usersControllerFindAll>>,
    TError,
    TData
  > & { queryKey: DataTag<QueryKey, TData, TError> };
};

export type UsersControllerFindAllQueryResult = NonNullable<
  Awaited<ReturnType<typeof usersControllerFindAll>>
>;
export type UsersControllerFindAllQueryError = unknown;

export function useUsersControllerFindAll<
  TData = Awaited<ReturnType<typeof usersControllerFindAll>>,
  TError = unknown,
>(options: {
  query: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof usersControllerFindAll>>,
      TError,
      TData
    >
  > &
    Pick<
      DefinedInitialDataOptions<
        Awaited<ReturnType<typeof usersControllerFindAll>>,
        TError,
        TData
      >,
      "initialData"
    >;
}): DefinedUseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};
export function useUsersControllerFindAll<
  TData = Awaited<ReturnType<typeof usersControllerFindAll>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof usersControllerFindAll>>,
      TError,
      TData
    >
  > &
    Pick<
      UndefinedInitialDataOptions<
        Awaited<ReturnType<typeof usersControllerFindAll>>,
        TError,
        TData
      >,
      "initialData"
    >;
}): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};
export function useUsersControllerFindAll<
  TData = Awaited<ReturnType<typeof usersControllerFindAll>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof usersControllerFindAll>>,
      TError,
      TData
    >
  >;
}): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};

export function useUsersControllerFindAll<
  TData = Awaited<ReturnType<typeof usersControllerFindAll>>,
  TError = unknown,
>(options?: {
  query?: Partial<
    UseQueryOptions<
      Awaited<ReturnType<typeof usersControllerFindAll>>,
      TError,
      TData
    >
  >;
}): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
} {
  const queryOptions = getUsersControllerFindAllQueryOptions(options);

  const query = useQuery(queryOptions) as UseQueryResult<TData, TError> & {
    queryKey: DataTag<QueryKey, TData, TError>;
  };

  query.queryKey = queryOptions.queryKey;

  return query;
}

export const usersControllerFindOne = (id: string, signal?: AbortSignal) => {
  return axiosInstance<UserResponseDto>({
    url: `/api/users/${id}`,
    method: "GET",
    signal,
  });
};

export const getUsersControllerFindOneQueryKey = (id: string) => {
  return [`/api/users/${id}`] as const;
};

export const getUsersControllerFindOneQueryOptions = <
  TData = Awaited<ReturnType<typeof usersControllerFindOne>>,
  TError = unknown,
>(
  id: string,
  options?: {
    query?: Partial<
      UseQueryOptions<
        Awaited<ReturnType<typeof usersControllerFindOne>>,
        TError,
        TData
      >
    >;
  }
) => {
  const { query: queryOptions } = options ?? {};

  const queryKey =
    queryOptions?.queryKey ?? getUsersControllerFindOneQueryKey(id);

  const queryFn: QueryFunction<
    Awaited<ReturnType<typeof usersControllerFindOne>>
  > = ({ signal }) => usersControllerFindOne(id, signal);

  return {
    queryKey,
    queryFn,
    enabled: !!id,
    ...queryOptions,
  } as UseQueryOptions<
    Awaited<ReturnType<typeof usersControllerFindOne>>,
    TError,
    TData
  > & { queryKey: DataTag<QueryKey, TData, TError> };
};

export type UsersControllerFindOneQueryResult = NonNullable<
  Awaited<ReturnType<typeof usersControllerFindOne>>
>;
export type UsersControllerFindOneQueryError = unknown;

export function useUsersControllerFindOne<
  TData = Awaited<ReturnType<typeof usersControllerFindOne>>,
  TError = unknown,
>(
  id: string,
  options: {
    query: Partial<
      UseQueryOptions<
        Awaited<ReturnType<typeof usersControllerFindOne>>,
        TError,
        TData
      >
    > &
      Pick<
        DefinedInitialDataOptions<
          Awaited<ReturnType<typeof usersControllerFindOne>>,
          TError,
          TData
        >,
        "initialData"
      >;
  }
): DefinedUseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};
export function useUsersControllerFindOne<
  TData = Awaited<ReturnType<typeof usersControllerFindOne>>,
  TError = unknown,
>(
  id: string,
  options?: {
    query?: Partial<
      UseQueryOptions<
        Awaited<ReturnType<typeof usersControllerFindOne>>,
        TError,
        TData
      >
    > &
      Pick<
        UndefinedInitialDataOptions<
          Awaited<ReturnType<typeof usersControllerFindOne>>,
          TError,
          TData
        >,
        "initialData"
      >;
  }
): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};
export function useUsersControllerFindOne<
  TData = Awaited<ReturnType<typeof usersControllerFindOne>>,
  TError = unknown,
>(
  id: string,
  options?: {
    query?: Partial<
      UseQueryOptions<
        Awaited<ReturnType<typeof usersControllerFindOne>>,
        TError,
        TData
      >
    >;
  }
): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
};

export function useUsersControllerFindOne<
  TData = Awaited<ReturnType<typeof usersControllerFindOne>>,
  TError = unknown,
>(
  id: string,
  options?: {
    query?: Partial<
      UseQueryOptions<
        Awaited<ReturnType<typeof usersControllerFindOne>>,
        TError,
        TData
      >
    >;
  }
): UseQueryResult<TData, TError> & {
  queryKey: DataTag<QueryKey, TData, TError>;
} {
  const queryOptions = getUsersControllerFindOneQueryOptions(id, options);

  const query = useQuery(queryOptions) as UseQueryResult<TData, TError> & {
    queryKey: DataTag<QueryKey, TData, TError>;
  };

  query.queryKey = queryOptions.queryKey;

  return query;
}

export const usersControllerUpdateUser = (
  id: string,
  updateUserDto: UpdateUserDto
) => {
  return axiosInstance<void>({
    url: `/api/users/${id}`,
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    data: updateUserDto,
  });
};

export const getUsersControllerUpdateUserMutationOptions = <
  TData = Awaited<ReturnType<typeof usersControllerUpdateUser>>,
  TError = unknown,
  TContext = unknown,
>(options?: {
  mutation?: UseMutationOptions<
    TData,
    TError,
    { id: string; data: UpdateUserDto },
    TContext
  >;
}) => {
  const mutationKey = ["usersControllerUpdateUser"];
  const { mutation: mutationOptions } = options
    ? options.mutation &&
      "mutationKey" in options.mutation &&
      options.mutation.mutationKey
      ? options
      : { ...options, mutation: { ...options.mutation, mutationKey } }
    : { mutation: { mutationKey } };

  const mutationFn: MutationFunction<
    Awaited<ReturnType<typeof usersControllerUpdateUser>>,
    { id: string; data: UpdateUserDto }
  > = (props) => {
    const { id, data } = props ?? {};

    return usersControllerUpdateUser(id, data);
  };

  return { mutationFn, ...mutationOptions } as UseMutationOptions<
    TData,
    TError,
    { id: string; data: UpdateUserDto },
    TContext
  >;
};

export type UsersControllerUpdateUserMutationResult = NonNullable<
  Awaited<ReturnType<typeof usersControllerUpdateUser>>
>;
export type UsersControllerUpdateUserMutationBody = UpdateUserDto;
export type UsersControllerUpdateUserMutationError = unknown;

export const useUsersControllerUpdateUser = <
  TData = Awaited<ReturnType<typeof usersControllerUpdateUser>>,
  TError = unknown,
  TContext = unknown,
>(options?: {
  mutation?: UseMutationOptions<
    TData,
    TError,
    { id: string; data: UpdateUserDto },
    TContext
  >;
}): UseMutationResult<
  TData,
  TError,
  { id: string; data: UpdateUserDto },
  TContext
> => {
  const mutationOptions = getUsersControllerUpdateUserMutationOptions(options);

  return useMutation(mutationOptions);
};

export const usersControllerRemoveUser = (id: string) => {
  return axiosInstance<void>({ url: `/api/users/${id}`, method: "DELETE" });
};

export const getUsersControllerRemoveUserMutationOptions = <
  TData = Awaited<ReturnType<typeof usersControllerRemoveUser>>,
  TError = unknown,
  TContext = unknown,
>(options?: {
  mutation?: UseMutationOptions<TData, TError, { id: string }, TContext>;
}) => {
  const mutationKey = ["usersControllerRemoveUser"];
  const { mutation: mutationOptions } = options
    ? options.mutation &&
      "mutationKey" in options.mutation &&
      options.mutation.mutationKey
      ? options
      : { ...options, mutation: { ...options.mutation, mutationKey } }
    : { mutation: { mutationKey } };

  const mutationFn: MutationFunction<
    Awaited<ReturnType<typeof usersControllerRemoveUser>>,
    { id: string }
  > = (props) => {
    const { id } = props ?? {};

    return usersControllerRemoveUser(id);
  };

  return { mutationFn, ...mutationOptions } as UseMutationOptions<
    TData,
    TError,
    { id: string },
    TContext
  >;
};

export type UsersControllerRemoveUserMutationResult = NonNullable<
  Awaited<ReturnType<typeof usersControllerRemoveUser>>
>;

export type UsersControllerRemoveUserMutationError = unknown;

export const useUsersControllerRemoveUser = <
  TData = Awaited<ReturnType<typeof usersControllerRemoveUser>>,
  TError = unknown,
  TContext = unknown,
>(options?: {
  mutation?: UseMutationOptions<TData, TError, { id: string }, TContext>;
}): UseMutationResult<TData, TError, { id: string }, TContext> => {
  const mutationOptions = getUsersControllerRemoveUserMutationOptions(options);

  return useMutation(mutationOptions);
};
