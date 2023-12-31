import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class User {

  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true , nullable: false })
  username: string;

  @Column({ unique: true , nullable: false })
  email: string;

  @Column({nullable: false})
  password: string;

  constructor(email:string, username:string, password:string){
    this.email = email;
    this.password = password;
    this.username = username;
  }
}
