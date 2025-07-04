import { Controller, Get, Param, ParseIntPipe } from '@nestjs/common';
import { ApiResponse, ApiTags } from '@nestjs/swagger';
import { NatsService } from 'src/common';

@ApiTags('practice')
@Controller('practice')
export class PracticeController {
  constructor(private readonly nats: NatsService) {}

  @Get('hello')
  @ApiResponse({
    status: 200,
    description: 'Saludo básico desde un microservicio',
  })
  async hello() {
    return this.nats.send('person.hello', {});
  }
  
    @Get('hello/:id')
    @ApiResponse({
      status: 200,
      description: 'Hello Person with ID',
    })
    async helloWithId(@Param('id', ParseIntPipe) id: number) {
      return this.nats.send('person.helloPersonWithId', { id });
    }
    
}
