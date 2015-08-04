class User < ActiveRecord::Base

  has_many :questions
  has_many :answers
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
  def is_admin?
    return self.admin == true
  end       
end
