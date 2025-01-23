import { Role } from "@nest-next-auth/database";
import { SetMetadata } from "@nestjs/common";

export const ROLES_KEY = "roles";
export const RestrictTo = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
