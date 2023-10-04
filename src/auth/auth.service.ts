import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
import { RegisterDto } from './dto/register.dto';
import { User } from 'src/users/entities/user.entity';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(private usersService : UsersService,
              private jwtService : JwtService
              ){}
  
  async register(registerDto:RegisterDto){
    const user = await this.usersService.findOneByEmail(registerDto.email);

    if(user){
      throw new BadRequestException('el usuario no existe al momento de la creacion')
    }
    const pass_encryptada = await bcrypt.hash(registerDto.password , 10); 
    return await this.usersService.create( new User (registerDto.email, registerDto.username, pass_encryptada))
  }
// async login ({email , password}: LoginDto) es igual a: async login (loginDto: LoginDto)
  async login (loginDto: LoginDto){
    const user : User = await this.usersService.findOneByEmail(loginDto.email);
    console.log(user);
    // verifico si el usuario existe
    if(!user)
    throw new UnauthorizedException('usuario incorrecto');
    // guardo en un variable (boolean) si el password no encriptado y el encriptado son iguales
    const isPasswordValid = await bcrypt.compare(loginDto.password, user.password)
    if(!isPasswordValid)
    throw new UnauthorizedException('password incorrecto');
  // es mala practica informar si el password o usuario es incorrecto - usar msj de usuario o password incorrecto

  // implemento jwt
  //creamos el payload para poder conocer info del token
  const payload = { email: user.email }
// por medio del metodo signAsyn paso el payload y genera el token... retorno el token
  const token = await this.jwtService.signAsync(payload);

  return token;
  }

}
