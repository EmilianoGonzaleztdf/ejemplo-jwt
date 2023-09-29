import { BadRequestException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
import { RegisterDto } from './dto/register.dto';
import { User } from 'src/users/entities/user.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private usersService : UsersService,
              //private jwtService : JwtService
              ){}
  
  async register(registerDto:RegisterDto){
    const user = await this.usersService.findOneByEmail(registerDto.email);

    if(user){
      throw new BadRequestException('el usuario no existe al momento de la creacion')
    }
    const pass_encryptada = await bcrypt.hash(registerDto.password , 10); 
    return await this.usersService.create( new User (registerDto.email, pass_encryptada ,registerDto.username))
  }
}
