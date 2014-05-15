module Spree
  module Permissions
    def method_missing(name, *args, &block)
      if name.to_s.starts_with?('can')
        can, action, subject, attribute = find_action_and_subject(name)

        Permissions.send(:define_method, name) do |current_ability, user|
          if attribute.nil?
            current_ability.send(can, action, subject)
          else
            current_ability.send(can, action, subject, attribute)
          end
        end
        send(name, args[0], args[1]) if self.respond_to?(name)
      else
        super
      end
    end

    define_method('default-permissions') do |current_ability, user|
      default_abilities_everyone_should_have current_ability, user
    end

    define_method('default-admin-permissions') do |current_ability, user|
      current_ability.can :admin, Spree::Order
      current_ability.can :index, Spree::Order
      default_abilities_everyone_should_have current_ability, user
    end

    define_method('can-update-spree/users') do |current_ability, user|
      current_ability.can :update, Spree::User
      # The permission of cannot update role_ids was given to user so that no onw with this permission can change role of user.
      current_ability.cannot :update, Spree::User, :role_ids
      default_abilities_everyone_should_have
    end

    define_method('can-create-spree/users') do |current_ability, user|
      current_ability.can :create, Spree::User
      current_ability.cannot :create, Spree::User, :role_ids
      default_abilities_everyone_should_have current_ability, user
    end

    private
      def default_abilities_everyone_should_have current_ability, user
        current_ability.can :create, Spree.user_class
        current_ability.can [:read, :update, :destroy], Spree.user_class do |resource|
          resource == user
        end

        current_ability.can [:read, :update], Spree::Order do |order, token|
          order.user == user || (order.token && token == order.token)
        end

        current_ability.can :create, Spree::Order
        current_ability.can :read, Spree::Address do |address|
          address.user == user
        end

        current_ability.can [:index, :read], Spree::Country
        current_ability.can [:index, :read], Spree::OptionType
        current_ability.can [:index, :read], Spree::OptionValue
        current_ability.can [:index, :read], Spree::Product
        current_ability.can [:index, :read], Spree::ProductProperty
        current_ability.can [:index, :read], Spree::Property
        current_ability.can [:index, :read], Spree::State
        current_ability.can [:index, :read], Spree::Taxon
        current_ability.can [:index, :read], Spree::Taxonomy
        current_ability.can [:index, :read], Spree::Variant
        current_ability.can [:index, :read], Spree::Zone
      end

      def find_action_and_subject(name)
        can, action, subject, attribute = name.to_s.split('-')

        if subject == 'all'
          return can.to_sym, action.to_sym, subject.to_sym, attribute.try(:to_sym)
        elsif (subject_class = subject.classify.safe_constantize) && subject_class.ancestors.include?(ActiveRecord::Base)
          return can.to_sym, action.to_sym, subject_class, attribute.try(:to_sym)
        else
          return can.to_sym, action.to_sym, subject, attribute.try(:to_sym)
        end
      end
  end
end
