import { ExtractJwt, Strategy } from "passport-jwt";

import { UnauthorizedException } from "@/common/errors";
import { ApiConfigService } from "@/config/config.service";
import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";

import { USER_CREDENTIALS_NOT_FOUND_ERROR_MESSAGE } from "../auth.constants";
import { AuthService } from "../auth.service";
import { JwtPayload, JwtTokenType } from "../jwt-token/jwt-token.types";

@Injectable()
export class RefreshJwtStrategy extends PassportStrategy(
  Strategy,
  "refresh-jwt"
) {
  constructor(
    private readonly apiConfigService: ApiConfigService,
    private readonly authService: AuthService
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: apiConfigService.refreshJwtPublicKey,
    });
  }

  async validate(payload: JwtPayload) {
    if (payload.type !== JwtTokenType.Refresh) {
      throw new UnauthorizedException(USER_CREDENTIALS_NOT_FOUND_ERROR_MESSAGE);
    }

    const user = await this.authService.validateJwtUser(payload.sub);

    if (!user) {
      throw new UnauthorizedException(USER_CREDENTIALS_NOT_FOUND_ERROR_MESSAGE);
    }

    return user;
  }
}
