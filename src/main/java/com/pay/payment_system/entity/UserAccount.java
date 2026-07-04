package com.pay.payment_system.entity;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(
        name = "users",
        indexes = {
                @Index(name = "idx_user_email_canonical", columnList = "email_canonical", unique = true),
                @Index(name = "idx_user_phone_number", columnList = "phone_number", unique = true)
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString(exclude = {"roles", "password", "security"})
public class UserAccount implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(nullable = false, length = 100)
    private String lastname;

    @Column(nullable = false, length = 255)
    private String password;

    @Column(name = "phone_number",unique = true, nullable = false, length = 10)
    private String mobileNumber;

    @Column(name = "email_canonical", unique = true, nullable = false, length = 254)
    private String emailCanonical;

    @Column(name = "email_dispatch", nullable = false, length = 254)
    private String emailDispatch;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "users_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @Singular
    private Set<Role> roles = new HashSet<>();

    @JsonManagedReference
    @OneToOne(
            mappedBy = "user",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.LAZY
    )
    private UserSecurity security;

    public void setSecurity(UserSecurity security) {
        this.security = security;
        if (security != null) {
            security.setUser(this);
        }
    }
}