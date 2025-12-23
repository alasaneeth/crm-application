import amqp from 'amqplib';
import Logger from '../../shared/config/logger.js';

const logger = new Logger('MessageQueue');

class MessageQueue {
  constructor() {
    this.connection = null;
    this.channel = null;
    this.queues = new Set();
  }

  async connect() {
    try {
      this.connection = await amqp.connect(process.env.RABBITMQ_URL || 'amqp://localhost');
      this.channel = await this.connection.createChannel();
      
      logger.info('Connected to RabbitMQ');
      
      // Ensure common exchanges exist
      await this.channel.assertExchange('user_events', 'topic', { durable: true });
      await this.channel.assertExchange('audit_logs', 'topic', { durable: true });
      
      // Reconnect handling
      this.connection.on('close', () => {
        logger.warn('RabbitMQ connection closed, attempting to reconnect...');
        setTimeout(() => this.connect(), 5000);
      });
      
    } catch (error) {
      logger.error('Failed to connect to RabbitMQ', { error: error.message });
      throw error;
    }
  }

  async publish(exchange, routingKey, message) {
    try {
      if (!this.channel) {
        await this.connect();
      }

      const messageBuffer = Buffer.from(JSON.stringify({
        ...message,
        timestamp: new Date().toISOString(),
        service: 'auth-service'
      }));

      this.channel.publish(exchange, routingKey, messageBuffer, {
        persistent: true,
        contentType: 'application/json'
      });

      logger.debug('Message published', { exchange, routingKey });
    } catch (error) {
      logger.error('Failed to publish message', { exchange, routingKey, error: error.message });
      throw error;
    }
  }

  async consume(queue, exchange, routingKey, callback) {
    try {
      if (!this.channel) {
        await this.connect();
      }

      // Assert queue
      await this.channel.assertQueue(queue, {
        durable: true,
        deadLetterExchange: 'dlx',
        deadLetterRoutingKey: queue
      });

      // Bind queue to exchange
      await this.channel.bindQueue(queue, exchange, routingKey);

      // Consume messages
      await this.channel.consume(queue, async (msg) => {
        if (msg !== null) {
          try {
            const content = JSON.parse(msg.content.toString());
            await callback(content);
            this.channel.ack(msg);
          } catch (error) {
            logger.error('Error processing message', { 
              queue, 
              error: error.message,
              content: msg.content.toString()
            });
            this.channel.nack(msg, false, false); // Don't requeue
          }
        }
      });

      this.queues.add(queue);
      logger.info(`Started consuming queue: ${queue}`);
    } catch (error) {
      logger.error('Failed to setup consumer', { queue, error: error.message });
      throw error;
    }
  }

  async disconnect() {
    try {
      if (this.channel) {
        await this.channel.close();
      }
      if (this.connection) {
        await this.connection.close();
      }
      logger.info('Disconnected from RabbitMQ');
    } catch (error) {
      logger.error('Error disconnecting from RabbitMQ', { error: error.message });
    }
  }
}

// Singleton instance
const messageQueue = new MessageQueue();

// Connect on startup
messageQueue.connect().catch(error => {
  logger.error('Failed to initialize message queue', { error: error.message });
});

export default messageQueue;