import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  signup(dto: AuthDto) {
    return this.prisma.user.create({
      data: {
        email: dto.email,
        hash: dto.password,
      },
    });
  }

  signin() {
    return 'test signin';
  }
}
